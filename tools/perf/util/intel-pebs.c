/*
 * PEBSv3+ aux data support
 *  decode and dump aux data
 * 2016-2018 Tong Zhang <ztong@vt.edu>
 */

#include <endian.h>
#include <byteswap.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/log2.h>

#include "cpumap.h"
#include "color.h"
#include "evsel.h"
#include "evlist.h"
#include "machine.h"
#include "session.h"
#include "util.h"
#include "thread.h"
#include "thread-stack.h"
#include "debug.h"
#include "tsc.h"
#include "auxtrace.h"
#include "intel-pebs.h"

#define MAX_TIMESTAMP (~0ULL)

#define INTEL_PEBS_ERR_NOINSN  5
#define INTEL_PEBS_ERR_LOST    9

#if __BYTE_ORDER == __BIG_ENDIAN
#define le64_to_cpu bswap_64
#else
#define le64_to_cpu
#endif

struct intel_pebs {
	struct auxtrace			auxtrace;
	struct auxtrace_queues		queues;
	struct auxtrace_heap		heap;
	u32				auxtrace_type;
	struct perf_session		*session;
	struct machine			*machine;
	bool				sampling_mode;
	bool				snapshot_mode;
	bool				data_queued;
	u32				pmu_type;
	struct perf_tsc_conversion	tc;
	bool				cap_user_time_zero;
	struct itrace_synth_opts	synth_opts;
    u64                 id;
	bool				synth_needs_swap;
};

struct intel_pebs_queue {
	struct intel_pebs	*pebs;
	unsigned int		queue_nr;
	struct auxtrace_buffer	*buffer;
	bool			on_heap;
	bool			done;
	pid_t			pid;
	pid_t			tid;
	int			cpu;
	u64			time;
};

struct pebs_record_skl {
	u64 flags, ip;
	u64 ax, bx, cx, dx;
	u64 si, di, bp, sp;
	u64 r8,  r9,  r10, r11;
	u64 r12, r13, r14, r15;
	u64 status, dla, dse, lat;
	u64 real_ip, tsx_tuning;
	u64 tsc;
};

static void intel_pebs_dump(struct intel_pebs *pebs __maybe_unused,
			   unsigned char *buf, size_t len)
{
	struct pebs_record_skl *pebs_record;
	size_t i, pos = 0, pebs_sz = sizeof(struct pebs_record_skl), sz;
	const char *color = PERF_COLOR_BLUE;

	color_fprintf(stdout, color,
		      ". ... Intel PEBS data: size %zu bytes\n",
		      len);

	while (len) {
		if (len >= pebs_sz)
			sz = pebs_sz;
		else
			sz = len;
		printf(".");
		color_fprintf(stdout, color, "  %08x: ", pos);
#if 0
		for (i = 0; i < sz; i++)
			color_fprintf(stdout, color, " %02x", buf[i]);
#endif
		fprintf(stdout,"\n");
		for (; i < pebs_sz; i++)
			color_fprintf(stdout, color, "   ");
		if (len >= pebs_sz) {
			pebs_record = (struct pebs_record_skl *)buf;
			fprintf(stdout,
				"+\t"
				"FLAG: 0x%"PRIx64"\t"
				"IP: 0x%"PRIx64"  \n"
				"+\t"
				"AX: 0x%"PRIx64"\t"
				"BX: 0x%"PRIx64"\n"
				"+\t"
				"CX: 0x%"PRIx64"\t"
				"DX: 0x%"PRIx64"\n"
				"+\t"
				"SI: 0x%"PRIx64"\t"
				"DI: 0x%"PRIx64"\n"
				"+\t"
				"BP: 0x%"PRIx64"\t"
				"SP: 0x%"PRIx64"\n"
				"+\t"
				"R8: 0x%"PRIx64"\t"
				"R9: 0x%"PRIx64"\n"
				"+\t"
				"R10: 0x%"PRIx64"\t"
				"R11: 0x%"PRIx64"\n"
				"+\t"
				"R12: 0x%"PRIx64"\t"
				"R13: 0x%"PRIx64"\n"
				"+\t"
				"R14: 0x%"PRIx64"\t"
				"R15: 0x%"PRIx64"\n",
				le64_to_cpu(pebs_record->flags),
				le64_to_cpu(pebs_record->ip),
				le64_to_cpu(pebs_record->ax),
				le64_to_cpu(pebs_record->bx),
				le64_to_cpu(pebs_record->cx),
				le64_to_cpu(pebs_record->dx),
				le64_to_cpu(pebs_record->si),
				le64_to_cpu(pebs_record->di),
				le64_to_cpu(pebs_record->bp),
				le64_to_cpu(pebs_record->sp),
				le64_to_cpu(pebs_record->r8),
				le64_to_cpu(pebs_record->r9),
				le64_to_cpu(pebs_record->r10),
				le64_to_cpu(pebs_record->r11),
				le64_to_cpu(pebs_record->r12),
				le64_to_cpu(pebs_record->r13),
				le64_to_cpu(pebs_record->r14),
				le64_to_cpu(pebs_record->r15)
				);
		} else {
			color_fprintf(stdout, color, " Bad record!\n");
		}
		pos += sz;
		buf += sz;
		len -= sz;
	}
}

static void intel_pebs_dump_event(struct intel_pebs *pebs, unsigned char *buf,
				 size_t len)
{
	printf(".\n");
	intel_pebs_dump(pebs, buf, len);
}

static int intel_pebs_lost(struct intel_pebs *pebs, struct perf_sample *sample)
{
	union perf_event event;
	int err;

	auxtrace_synth_error(&event.auxtrace_error, PERF_AUXTRACE_ERROR_ITRACE,
			     INTEL_PEBS_ERR_LOST, sample->cpu, sample->pid,
			     sample->tid, 0, "Lost trace data");

	err = perf_session__deliver_synth_event(pebs->session, &event, NULL);
	if (err)
		pr_err("Intel PEBS: failed to deliver error event, error %d\n",
		       err);

	return err;
}

static struct intel_pebs_queue *intel_pebs_alloc_queue(struct intel_pebs *pebs,
						     unsigned int queue_nr)
{
	struct intel_pebs_queue *pebsq;

	pebsq = zalloc(sizeof(struct intel_pebs_queue));
	if (!pebsq)
		return NULL;

	pebsq->pebs = pebs;
	pebsq->queue_nr = queue_nr;
	pebsq->pid = -1;
	pebsq->tid = -1;
	pebsq->cpu = -1;

	return pebsq;
}

static int intel_pebs_setup_queue(struct intel_pebs *pebs,
				 struct auxtrace_queue *queue,
				 unsigned int queue_nr)
{
	struct intel_pebs_queue *pebsq = queue->priv;

	if (list_empty(&queue->head))
		return 0;

	if (!pebsq) {
		pebsq = intel_pebs_alloc_queue(pebs, queue_nr);
		if (!pebsq)
			return -ENOMEM;
		queue->priv = pebsq;

		if (queue->cpu != -1)
			pebsq->cpu = queue->cpu;
		pebsq->tid = queue->tid;
	}

	if (pebs->sampling_mode)
		return 0;

	if (!pebsq->on_heap && !pebsq->buffer) {
		int ret;

		pebsq->buffer = auxtrace_buffer__next(queue, NULL);
		if (!pebsq->buffer)
			return 0;

		ret = auxtrace_heap__add(&pebs->heap, queue_nr,
					 pebsq->buffer->reference);
		if (ret)
			return ret;
		pebsq->on_heap = true;
	}

	return 0;
}

static int intel_pebs_setup_queues(struct intel_pebs *pebs)
{
	unsigned int i;
	int ret;

	for (i = 0; i < pebs->queues.nr_queues; i++) {
		ret = intel_pebs_setup_queue(pebs, &pebs->queues.queue_array[i],
					    i);
		if (ret)
			return ret;
	}
	return 0;
}

static inline int intel_pebs_update_queues(struct intel_pebs *pebs)
{
	if (pebs->queues.new_data) {
		pebs->queues.new_data = false;
		return intel_pebs_setup_queues(pebs);
	}
	return 0;
}

static int intel_pebs_synth_raw_sample(struct intel_pebs_queue *pebsq,
					 struct pebs_record_skl *pebs_record)
{
	int ret;
	struct intel_pebs *pebs = pebsq->pebs;
	union perf_event event;
	struct perf_sample sample = { .ip = 0, };
	
	//dump data from aux buffer to prepared sample
	event.sample.header.type = PERF_RECORD_SAMPLE;
	event.sample.header.misc = PERF_RECORD_MISC_USER;
	event.sample.header.size = sizeof(struct perf_event_header);

	sample.ip = pebs_record->ip;
	sample.pid = pebsq->pid;
	sample.tid = pebsq->tid;
	sample.addr = pebs_record->real_ip;
	sample.period = 1;
	sample.cpu = pebsq->cpu;
    sample.time = tsc_to_perf_time(pebs_record->tsc, &pebs->tc);
    sample.flags = 0;
    sample.id = pebs->id;
    sample.stream_id = pebs->id;

    sample.user_regs.mask = 0x0FF03FF;
    sample.user_regs.regs = malloc(sizeof(u64)*8*18);
    sample.user_regs.regs[0] = pebs_record->ax;
    sample.user_regs.regs[1] = pebs_record->bx;
    sample.user_regs.regs[2] = pebs_record->cx;
    sample.user_regs.regs[3] = pebs_record->dx;
    sample.user_regs.regs[4] = pebs_record->si;
    sample.user_regs.regs[5] = pebs_record->di;
    sample.user_regs.regs[6] = pebs_record->bp;
    sample.user_regs.regs[7] = pebs_record->sp;
    sample.user_regs.regs[8] = pebs_record->ip;
    sample.user_regs.regs[9] = pebs_record->flags;
    sample.user_regs.regs[10] = pebs_record->r8;
    sample.user_regs.regs[11] = pebs_record->r9;
    sample.user_regs.regs[12] = pebs_record->r10;
    sample.user_regs.regs[13] = pebs_record->r11;
    sample.user_regs.regs[14] = pebs_record->r12;
    sample.user_regs.regs[15] = pebs_record->r13;
    sample.user_regs.regs[16] = pebs_record->r14;
    sample.user_regs.regs[17] = pebs_record->r15;

#if 1
	//FIXME! need inject???
	if (pebs->synth_opts.inject) {
    //if (1){
		ret = perf_event__synthesize_sample(&event,
						    PERF_SAMPLE_IP | PERF_SAMPLE_TID |
                            PERF_SAMPLE_REGS_USER | PERF_SAMPLE_TIME |
                            PERF_SAMPLE_PERIOD | PERF_SAMPLE_CPU |
                            PERF_SAMPLE_ADDR ,
						    0, &sample,
						    pebs->synth_needs_swap);
		if (ret)
        {
            free(sample.user_regs.regs);
			return ret;
        }
	}
#endif
	ret = perf_session__deliver_synth_event(pebs->session, &event, &sample);
	if (ret)
		pr_err("Intel PEBS: failed to deliver event, error %d\n",
		       ret);
    free(sample.user_regs.regs);
	return ret;
}

static int intel_pebs_process_buffer(struct intel_pebs_queue *pebsq,
				    struct auxtrace_buffer *buffer)
{
	struct pebs_record_skl *pebs_record;
	size_t sz, psz = sizeof(struct pebs_record_skl);
	int err = 0;

	if (buffer->use_data) {
		sz = buffer->use_size;
		pebs_record = buffer->use_data;
	} else {
		sz = buffer->size;
		pebs_record = buffer->data;
	}
	for (; sz > psz; pebs_record += 1, sz -= psz) {
        //discard padding records
        if (pebs_record->ip==0)
        {
            continue;
        }
		err = intel_pebs_synth_raw_sample(pebsq, pebs_record);
		if (err)
			break;
	}
	return err;
}

static int intel_pebs_process_queue(struct intel_pebs_queue *pebsq, u64 *timestamp)
{
	struct auxtrace_buffer *buffer = pebsq->buffer, *old_buffer = buffer;
	struct auxtrace_queue *queue;
	struct thread *thread;
	int err = 0;

	if (pebsq->done)
		return 1;

	if (pebsq->pid == -1) {
		thread = machine__find_thread(pebsq->pebs->machine, -1,
					      pebsq->tid);
		if (thread)
			pebsq->pid = thread->pid_;
	} else {
		thread = machine__findnew_thread(pebsq->pebs->machine, pebsq->pid,
						 pebsq->tid);
	}

	queue = &pebsq->pebs->queues.queue_array[pebsq->queue_nr];

	if (!buffer)
		buffer = auxtrace_buffer__next(queue, NULL);

	if (!buffer) {
		if (!pebsq->pebs->sampling_mode)
			pebsq->done = 1;
		err = 1;
		goto out_put;
	}

	/* Currently there is no support for split buffers */
	if (buffer->consecutive) {
		err = -EINVAL;
		goto out_put;
	}

	if (!buffer->data) {
		int fd = perf_data_file__fd(pebsq->pebs->session->file);

		buffer->data = auxtrace_buffer__get_data(buffer, fd);
		if (!buffer->data) {
			err = -ENOMEM;
			goto out_put;
		}
	}

	if (!pebsq->pebs->synth_opts.callchain && thread &&
	    (!old_buffer || pebsq->pebs->sampling_mode ||
	     (pebsq->pebs->snapshot_mode && !buffer->consecutive)))
		thread_stack__set_trace_nr(thread, buffer->buffer_nr + 1);

	err = intel_pebs_process_buffer(pebsq, buffer);

	auxtrace_buffer__drop_data(buffer);

	pebsq->buffer = auxtrace_buffer__next(queue, buffer);
	if (pebsq->buffer) {
		if (timestamp)
			*timestamp = pebsq->buffer->reference;
	} else {
		if (!pebsq->pebs->sampling_mode)
			pebsq->done = 1;
	}
out_put:
	thread__put(thread);
	return err;
}

static int intel_pebs_flush_queue(struct intel_pebs_queue *pebsq)
{
	u64 ts = 0;
	int ret;

	while (1) {
		ret = intel_pebs_process_queue(pebsq, &ts);
		if (ret < 0)
			return ret;
		if (ret)
			break;
	}
	return 0;
}

static int intel_pebs_process_tid_exit(struct intel_pebs *pebs, pid_t tid)
{
	struct auxtrace_queues *queues = &pebs->queues;
	unsigned int i;

	for (i = 0; i < queues->nr_queues; i++) {
		struct auxtrace_queue *queue = &pebs->queues.queue_array[i];
		struct intel_pebs_queue *pebsq = queue->priv;

		if (pebsq && pebsq->tid == tid)
			return intel_pebs_flush_queue(pebsq);
	}
	return 0;
}

static int intel_pebs_process_queues(struct intel_pebs *pebs, u64 timestamp)
{
	while (1) {
		unsigned int queue_nr;
		struct auxtrace_queue *queue;
		struct intel_pebs_queue *pebsq;
		u64 ts = 0;
		int ret;

		if (!pebs->heap.heap_cnt)
			return 0;

		if (pebs->heap.heap_array[0].ordinal > timestamp)
			return 0;

		queue_nr = pebs->heap.heap_array[0].queue_nr;
		queue = &pebs->queues.queue_array[queue_nr];
		pebsq = queue->priv;

		auxtrace_heap__pop(&pebs->heap);

		ret = intel_pebs_process_queue(pebsq, &ts);
		if (ret < 0) {
			auxtrace_heap__add(&pebs->heap, queue_nr, ts);
			return ret;
		}

		if (!ret) {
			ret = auxtrace_heap__add(&pebs->heap, queue_nr, ts);
			if (ret < 0)
				return ret;
		} else {
			pebsq->on_heap = false;
		}
	}

	return 0;
}

static int intel_pebs_process_event(struct perf_session *session,
				   union perf_event *event,
				   struct perf_sample *sample,
				   struct perf_tool *tool)
{
	struct intel_pebs *pebs = 
		container_of(session->auxtrace_pebs, struct intel_pebs, auxtrace);
	u64 timestamp;
	int err;
    //if event is not pebs we should not come here
    if (event->header.type!=PERF_RECORD_AUXTRACE)
    {
        return 0;
    }
    if (event->auxtrace.pmu!=PERF_AUXTRACE_INTEL_PEBS)
    {
        return 0;
    }

	if (dump_trace)
		return 0;

	if (!tool->ordered_events) {
		pr_err("Intel PEBS requires ordered events\n");
		return -EINVAL;
	}

	if (sample->time && sample->time != (u64)-1)
		timestamp = perf_time_to_tsc(sample->time, &pebs->tc);
	else
		timestamp = 0;

	err = intel_pebs_update_queues(pebs);
	if (err)
		return err;

	err = intel_pebs_process_queues(pebs, timestamp);
	if (err)
		return err;
	if (event->header.type == PERF_RECORD_EXIT) {
		err = intel_pebs_process_tid_exit(pebs, event->fork.tid);
		if (err)
			return err;
	}

	if (event->header.type == PERF_RECORD_AUX &&
	    (event->aux.flags & PERF_AUX_FLAG_TRUNCATED) &&
	    pebs->synth_opts.errors)
		err = intel_pebs_lost(pebs, sample);

	return err;
}

static int intel_pebs_process_auxtrace_event(struct perf_session *session,
					    union perf_event *event,
					    struct perf_tool *tool __maybe_unused)
{
	struct intel_pebs *pebs = 
		container_of(session->auxtrace_pebs, struct intel_pebs, auxtrace);

    //if event is not pebs we should not come here
    if (event->header.type!=PERF_RECORD_AUXTRACE)
    {
        return 0;
    }
    //printf("auxtrace type:%d\n",event->auxtrace.pmu);
    if (event->auxtrace.pmu!=PERF_AUXTRACE_INTEL_PEBS)
    {
        return 0;
    }

	if (pebs->sampling_mode)
		return 0;

    pr_debug("pebs->data_queued?=%d\n",pebs->data_queued);
	if (!pebs->data_queued) {
		struct auxtrace_buffer *buffer;
		off_t data_offset;
		int fd = perf_data_file__fd(session->file);
		int err;

		if (perf_data_file__is_pipe(session->file)) {
			data_offset = 0;
		} else {
			data_offset = lseek(fd, 0, SEEK_CUR);
			if (data_offset == -1)
				return -errno;
		}

		err = auxtrace_queues__add_event(&pebs->queues, session, event,
						 data_offset, &buffer);
        pr_debug("added one pebs auxtrace event\n");
		if (err)
			return err;

		/* Dump here now we have copied a piped trace out of the pipe */
		if (dump_trace) {
			if (auxtrace_buffer__get_data(buffer, fd)) {
				intel_pebs_dump_event(pebs, buffer->data,
						     buffer->size);
				auxtrace_buffer__put_data(buffer);
			}
		}
	}

	return 0;
}

static int intel_pebs_flush(struct perf_session *session __maybe_unused,
			   struct perf_tool *tool __maybe_unused)
{
	struct intel_pebs *pebs = 
		container_of(session->auxtrace_pebs, struct intel_pebs, auxtrace);
	int ret;

	if (dump_trace || pebs->sampling_mode)
		return 0;

	if (!tool->ordered_events)
		return -EINVAL;

	ret = intel_pebs_update_queues(pebs);
	if (ret < 0)
		return ret;
	return intel_pebs_process_queues(pebs, MAX_TIMESTAMP);
}

static void intel_pebs_free_queue(void *priv)
{
	struct intel_pebs_queue *pebsq = priv;

	if (!pebsq)
		return;
	free(pebsq);
}

static void intel_pebs_free_events(struct perf_session *session)
{
	struct intel_pebs *pebs = 
		container_of(session->auxtrace_pebs, struct intel_pebs, auxtrace);
	struct auxtrace_queues *queues = &pebs->queues;
	unsigned int i;

	for (i = 0; i < queues->nr_queues; i++) {
		intel_pebs_free_queue(queues->queue_array[i].priv);
		queues->queue_array[i].priv = NULL;
	}
	auxtrace_queues__free(queues);
}

static void intel_pebs_free(struct perf_session *session)
{
	struct intel_pebs *pebs = container_of(session->auxtrace_pebs, struct intel_pebs,
					     auxtrace);

	auxtrace_heap__free(&pebs->heap);
	intel_pebs_free_events(session);
	session->auxtrace_pebs = NULL;
	free(pebs);
}

struct intel_pebs_synth {
	struct perf_tool dummy_tool;
	struct perf_session *session;
};

static int intel_pebs_event_synth(struct perf_tool *tool,
				 union perf_event *event,
				 struct perf_sample *sample __maybe_unused,
				 struct machine *machine __maybe_unused)
{
	struct intel_pebs_synth *intel_pebs_synth =
			container_of(tool, struct intel_pebs_synth, dummy_tool);

	return perf_session__deliver_synth_event(intel_pebs_synth->session,
						 event, NULL);
}

static int intel_pebs_synth_event(struct perf_session *session,
				 struct perf_event_attr *attr, u64 id)
{
	struct intel_pebs_synth intel_pebs_synth;

	memset(&intel_pebs_synth, 0, sizeof(struct intel_pebs_synth));
	intel_pebs_synth.session = session;

	return perf_event__synthesize_attr(&intel_pebs_synth.dummy_tool, attr, 1,
					   &id, intel_pebs_event_synth);
}

static int intel_pebs_synth_events(struct intel_pebs *pebs,
				  struct perf_session *session)
{
	struct perf_evlist *evlist = session->evlist;
	struct perf_evsel *evsel;
	struct perf_event_attr attr;
	bool found = false;
	u64 id;
	int err;

	evlist__for_each(evlist, evsel) {
		if (evsel->attr.type == pebs->pmu_type && evsel->ids) {
			found = true;
			break;
		}
	}

	if (!found) {
		pr_debug("There are no selected events with Intel PEBS data\n");
		return 0;
	}

	memset(&attr, 0, sizeof(struct perf_event_attr));
	attr.size = sizeof(struct perf_event_attr);
	attr.type = PERF_TYPE_HARDWARE;
	attr.sample_type = evsel->attr.sample_type & PERF_SAMPLE_MASK;
	attr.sample_type |= PERF_SAMPLE_IP | PERF_SAMPLE_TID |
			    PERF_SAMPLE_PERIOD | PERF_SAMPLE_TIME |
                PERF_SAMPLE_CPU;
	attr.exclude_user = evsel->attr.exclude_user;
	attr.exclude_kernel = evsel->attr.exclude_kernel;
	attr.exclude_hv = evsel->attr.exclude_hv;
	attr.exclude_host = evsel->attr.exclude_host;
	attr.exclude_guest = evsel->attr.exclude_guest;
	attr.sample_id_all = evsel->attr.sample_id_all;
	attr.read_format = evsel->attr.read_format;

	id = evsel->id[0] + 2000000000;
	if (!id)
		id = 1;
#if 1
	if (pebs->synth_opts.instructions) {
		attr.config = PERF_COUNT_HW_INSTRUCTIONS;
		attr.sample_period = 1;
		attr.sample_type |= PERF_SAMPLE_ADDR;

		err = intel_pebs_synth_event(session, &attr, id);

		if (err) {
			pr_err("%s: failed to synthesize 'instructions' event type\n",
			       __func__);
			return err;
		}
        pebs->id = id;
	}
#endif
	pebs->synth_needs_swap = evsel->needs_swap;//???what's this???

	return 0;
}

static const char * const intel_pebs_info_fmts[] = {
	[INTEL_PEBS_PMU_TYPE]		= "  PMU Type           %"PRId64"\n",
	[INTEL_PEBS_TIME_SHIFT]		= "  Time Shift         %"PRIu64"\n",
	[INTEL_PEBS_TIME_MULT]		= "  Time Muliplier     %"PRIu64"\n",
	[INTEL_PEBS_TIME_ZERO]		= "  Time Zero          %"PRIu64"\n",
	[INTEL_PEBS_CAP_USER_TIME_ZERO]	= "  Cap Time Zero      %"PRId64"\n",
	[INTEL_PEBS_SNAPSHOT_MODE]	= "  Snapshot mode      %"PRId64"\n",
};

static void intel_pebs_print_info(u64 *arr, int start, int finish)
{
	int i;

	if (!dump_trace)
		return;

	for (i = start; i <= finish; i++)
		fprintf(stdout, intel_pebs_info_fmts[i], arr[i]);
}

u64 intel_pebs_auxtrace_info_priv[INTEL_PEBS_AUXTRACE_PRIV_SIZE];

int intel_pebs_process_auxtrace_info(union perf_event *event,
				    struct perf_session *session)
{
	struct auxtrace_info_event *auxtrace_info = &event->auxtrace_info;
	size_t min_sz = sizeof(u64) * INTEL_PEBS_SNAPSHOT_MODE;
	struct intel_pebs *pebs;
	int err;

	if (auxtrace_info->header.size < sizeof(struct auxtrace_info_event) +
					min_sz)
		return -EINVAL;

	pebs = zalloc(sizeof(struct intel_pebs));
	if (!pebs)
		return -ENOMEM;

	err = auxtrace_queues__init(&pebs->queues);
    //pebs->queues->pmu = PERF_AUXTRACE_INTEL_PEBS;

	if (err)
		goto err_free;

	pebs->session = session;
	pebs->machine = &session->machines.host; /* No kvm support */
	pebs->auxtrace_type = auxtrace_info->type;
	pebs->pmu_type = auxtrace_info->priv[INTEL_PEBS_PMU_TYPE];
	pebs->tc.time_shift = auxtrace_info->priv[INTEL_PEBS_TIME_SHIFT];
	pebs->tc.time_mult = auxtrace_info->priv[INTEL_PEBS_TIME_MULT];
	pebs->tc.time_zero = auxtrace_info->priv[INTEL_PEBS_TIME_ZERO];
	pebs->cap_user_time_zero =
			auxtrace_info->priv[INTEL_PEBS_CAP_USER_TIME_ZERO];
	pebs->snapshot_mode = auxtrace_info->priv[INTEL_PEBS_SNAPSHOT_MODE];

	pebs->sampling_mode = false;

	//setup callback function
	pebs->auxtrace.process_event = intel_pebs_process_event;
	pebs->auxtrace.process_auxtrace_event = intel_pebs_process_auxtrace_event;
	pebs->auxtrace.flush_events = intel_pebs_flush;
	pebs->auxtrace.free_events = intel_pebs_free_events;
	pebs->auxtrace.free = intel_pebs_free;
	//
	session->auxtrace_pebs = &pebs->auxtrace;

	intel_pebs_print_info(&auxtrace_info->priv[0], INTEL_PEBS_PMU_TYPE,
			     INTEL_PEBS_SNAPSHOT_MODE);

	if (dump_trace)
		return 0;

	if (session->itrace_synth_opts && session->itrace_synth_opts->set)
		pebs->synth_opts = *session->itrace_synth_opts;
	else
		itrace_synth_opts__set_default(&pebs->synth_opts);

	err = intel_pebs_synth_events(pebs, session);
	if (err)
		goto err_free_queues;

	/*err = auxtrace_queues__process_index(&pebs->queues, session);
	if (err)
		goto err_free_queues;

    printf("pebs->populated?=%d\n", pebs->queues.populated);
	if (pebs->queues.populated)
    {
		pebs->data_queued = true;
    }*/
	return 0;

err_free_queues:
	auxtrace_queues__free(&pebs->queues);
	session->auxtrace_pebs = NULL;
err_free:
	free(pebs);
	return err;
}

