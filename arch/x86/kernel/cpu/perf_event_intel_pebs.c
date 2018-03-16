/*
 * PEBSv3+ driver using AUX area
 * 2016-2017 Tong Zhang <ztong@vt.edu>
 */

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/coredump.h>

#include <asm-generic/sizes.h>
#include <asm/perf_event.h>

#include "perf_event.h"

//////////////////////

extern int x86_pmu_event_init(struct perf_event *event);
extern int x86_pmu_event_idx(struct perf_event *event);
extern void x86_pmu_del(struct perf_event *event, int flags);
extern int x86_pmu_add(struct perf_event *event, int flags);

extern void x86_pmu_enable(struct pmu*);
extern void x86_pmu_disable(struct pmu*);

extern void x86_add_intel_pebs_usage(void);
extern void x86_del_intel_pebs_usage(void);

extern const struct attribute_group *x86_pmu_attr_groups[];
////////////////////

#define _DEBUG_ 0
#define _DEBUG_DS_ 0

struct pebs_ctx {
	struct perf_output_handle   handle;
	struct debug_store  ds_back;
	int started;
	int valid;//is the ds backup valid?
    int aux_started;//already requested aux_begin
    int added_event;
}__attribute__((aligned(sizeof(u64))));

static DEFINE_PER_CPU(struct pebs_ctx, pebs_ctx);

struct pmu pebs_pmu;

/*
 * structure to hold page data
 */
struct pebs_phys {
	//pointer to physical page chunk
	struct page	*page;
	//size of this page chunk
	unsigned long	size;
};

struct pebs_buffer {
	//which cpu is this buffer belongs to
	int			cpu;
	//how many pages are there
	unsigned int		nr_pages;
	//how many buffers are these pages divided into
	unsigned int		nr_bufs;
	//which buffer is currently being used
	unsigned int 		cur_buf;
	bool			snapshot;
	//how much data has been collected in this buffer
	local_t			data_size;
	//how many times the data is lost
	local_t			lost;
	//index head in current buffer
	local_t			head;
	//pointer to the beginning of allocated page
	void			**data_pages;
	//structure to hold logical buffer data
	struct pebs_phys	buf[0];
};
#if _DEBUG_
static void dump_events(void)
{
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
    int i;
    printk("dumping events: %d\n", cpuc->n_events);
	for (i = 0; i < cpuc->n_events; i++)
    {
		struct perf_event * te = cpuc->events[i];
        union x86_pmu_config *cfg;
        if (te==NULL)
        {
            printk("@%d:null event\n", i);
            continue;
        }
        printk("@%d:pmu:%s, type:%d, sample_type:%llu, sample_period:%llu, config:0x%llx\n",
            i,
            te->pmu?te->pmu->name:"na",
            te->attr.type,
            te->attr.sample_type,
            te->attr.sample_period,
            te->attr.config);
        printk("...hwc->flags=0x%x\n", te->hw.flags);
        cfg =(union x86_pmu_config*) &(te->attr.config);
        printk("...uevent:%d, umask%d\n",cfg->bits.event, cfg->bits.umask);
	}
}
#endif

/*
 * backup current ds and recover ds
 */
inline static void backup_ds(struct pebs_ctx* pebs, struct cpu_hw_events *cpuc)
{
    if (!cpuc->ds)
    {
        printk("how come ds is NULL?!!!!\n");
        pebs->valid = 0;
        return;
    }
	pebs->ds_back.pebs_buffer_base = cpuc->ds->pebs_buffer_base;
	pebs->ds_back.pebs_index = cpuc->ds->pebs_index;
	pebs->ds_back.pebs_absolute_maximum = cpuc->ds->pebs_absolute_maximum;
	pebs->ds_back.pebs_interrupt_threshold 
		= cpuc->ds->pebs_interrupt_threshold;
	pebs->valid = 1;
    wmb();
}

inline static void recover_ds(struct pebs_ctx* pebs, struct cpu_hw_events *cpuc)
{
	if(pebs->valid)
	{
        if (!cpuc->ds)
        {
            printk("how come ds is NULL?!!!\n");
            pebs->valid = 0;
            return;
        }
		cpuc->ds->pebs_buffer_base = pebs->ds_back.pebs_buffer_base;
		cpuc->ds->pebs_index = pebs->ds_back.pebs_index;
		cpuc->ds->pebs_absolute_maximum = 
			pebs->ds_back.pebs_absolute_maximum;
		/*
		 * trick intel_pmu_pebs_disable to believe
		 * we are using large buffer, otherwise there will be problem!
		 */
		//cpuc->ds->pebs_interrupt_threshold 
		//	= pebs->ds_back.pebs_interrupt_threshold;
		cpuc->ds->pebs_interrupt_threshold
			= pebs->ds_back.pebs_buffer_base + 401;
		pebs->valid = 0;
        wmb();
	}
}

/*
 * pebs_buffer_setup_aux() - set up debug store for PEBS
 * @cpu:	CPU on which to allocate, -1 means current
 * @pages:	Array of pointers to buffer pages passed from perf core
 * @nr_pages:	Number of pages in the buffer
 * @snapshot:	If this is a snapshot/overwrite counter
 *
 * This is a pmu::setup_aux callback that sets up Debug Store and all the
 * bookkeeping for an AUX buffer
 *
 * Return:	Our private PEBS buffer structure
 *
 */
void*
pebs_buffer_setup_aux(int cpu, void **pages, int nr_pages, bool overwrite)
{
	struct pebs_buffer *buf;
	struct page *page;
	int node = (cpu == -1) ? cpu : cpu_to_node(cpu);
	int pg, nbuf, pad;

	/* count all the high order buffers */
	for (pg = 0, nbuf = 0; pg < nr_pages;) {
		page = virt_to_page(pages[pg]);
		if(WARN_ON_ONCE((!PagePrivate(page)) && (nr_pages > 1)))
			return NULL;
		pg += 1 << page_private(page);
		nbuf++;
	}
#if _DEBUG_
	printk("intel_pebs setup aux:"
	    "@cpu%d, page addr:%p, nr_pages:%d, x_nbuf:%d\n",
		cpu, pages, nr_pages, nbuf);
#endif	
	if (overwrite && (nbuf > 1))
		return NULL;

	buf = kzalloc_node(offsetof(struct pebs_buffer, buf[nbuf]),
			GFP_KERNEL, node);

	if (!buf)
		return NULL;
	buf->cpu = cpu;
	buf->nr_pages = nr_pages;
	buf->nr_bufs = nbuf;
	buf->snapshot = overwrite;
	buf->data_pages = pages;
	for (pg = 0, nbuf = 0, pad = 0;
			nbuf < buf->nr_bufs;
			nbuf++)
	{
		unsigned int __nr_pages;

		page = virt_to_page(pages[pg]);
		__nr_pages = PagePrivate(page) ? 1 << page_private(page) : 1;

		buf->buf[nbuf].page = page;
		buf->buf[nbuf].size = 1 << (PAGE_SHIFT + page_private(page));
		pg += __nr_pages;
#if _DEBUG_
        printk("buffer:%d %p + %d\n",
            nbuf,
            buf->buf[nbuf].page,
            buf->buf[nbuf].size);
#endif
	}
	return buf;
}

void pebs_buffer_free_aux(void *data)
{
#if _DEBUG_
	struct pebs_buffer *buf = (struct pebs_buffer*)data;
	printk("pebs_buffer_free_aux #cpu%d :\n",
			buf->cpu);
#endif
	kfree(data);
}

///////////////////////////////////////////////////////////////////////////////
#if 0
/*
 * is current buffer full?
 */
static bool pebs_buffer_is_full(struct pebs_buffer *buf)
{
	struct pebs_phys *phys = &buf->buf[buf->cur_buf];
	//struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
	//struct debug_store *ds = cpuc->ds;

#if _DEBUG_
	printk("@cpu(%d) pebs_buffer_is_full? free:%lu, critical:%d?\n",
			smp_processor_id(),
			(phys->size - local_read(&buf->head)),
			10 * x86_pmu.pebs_record_size);
#endif

	if (buf->snapshot)
		return false;

	if ((phys->size - local_read(&buf->head)) <=
			(10 * x86_pmu.pebs_record_size))
		return true;

	return false;
}
#endif
/*
 * config ds area to use new buffer area
 */
static void pebs_config_buffer(struct pebs_buffer* buf)
{

	int cpu = raw_smp_processor_id();

	struct debug_store *ds = per_cpu(cpu_hw_events, cpu).ds;
	struct pebs_phys *phys = &buf->buf[buf->cur_buf];
	struct page *page = phys->page;
    u64 buffer_base = (u64)(long)page_address(page);

	int max_sample = phys->size	/ x86_pmu.pebs_record_size;

    if (!ds)
    {
        printk("how come ds is NULL????!");
        return;
    }

	//set ds to use new buffer,
    //is buf->head == 0 anyway??
	ds->pebs_buffer_base = buffer_base + local_read(&buf->head);
	ds->pebs_index = ds->pebs_buffer_base;

	ds->pebs_absolute_maximum = ds->pebs_buffer_base
		+ (max_sample - 1) * x86_pmu.pebs_record_size + 1;
	/*
	 * keep ~2 records away from the max
	 * also, this one must be aligned to sample boundary
	 */
	ds->pebs_interrupt_threshold = ds->pebs_buffer_base
		+ (max_sample - 2) * x86_pmu.pebs_record_size;
#if (_DEBUG_ || _DEBUG_DS_)
	printk("pebs_ds_cfg @cpu%d :[0x%llx,0x%llx] T:0x%llx,"
			" {psize:0x%lx,head:0x%lx}\n",
			smp_processor_id(),
			ds->pebs_buffer_base,
			ds->pebs_absolute_maximum,
			ds->pebs_interrupt_threshold,
			phys->size,
			buf->head);
#endif
}

/*
 * check water level
 * advance head in current buffer before calling aux_output
 * update data_size
 */
static void pebs_update(struct pebs_ctx *pebs)
{
	int cpu = raw_smp_processor_id();
	struct debug_store *ds = per_cpu(cpu_hw_events, cpu).ds;
	struct pebs_buffer *buf = perf_get_aux_pebs(&pebs->handle);
	//current water level
	u64 data_size;
	//old offset in current buffer
	u64 old;
	//new offset in current buffer
	u64 head;
    if (!ds)
    {
        printk("How come ds is null???!!!\n");
        return;
    }

    data_size = ds->pebs_index - ds->pebs_buffer_base;

#if (_DEBUG_ || _DEBUG_DS_)
	printk("@cpu(%d) pebs_update: "
		" base,index:(0x%llx,0x%llx)\n",
		cpu, ds->pebs_buffer_base, ds->pebs_index);
#endif
	if (!buf)
		return;

	head = data_size;
	old = local_xchg(&buf->head, head);

	if (!buf->snapshot) {
		if (old == head)
			return;

		if (ds->pebs_index >= ds->pebs_absolute_maximum)
			local_inc(&buf->lost);
		
		local_add(head-old, &buf->data_size);
	} else {
		local_set(&buf->data_size, head);
	}
#if (_DEBUG_ || _DEBUG_DS_)
	printk("@(cpu%d) pebs_update: size %ld @ head %ld\n",
			smp_processor_id(),
			buf->data_size,
			buf->head);
#endif
}

/*
 * check buffer usage
 * exchange buffer if current buffer is exhausted
 */
static int pebs_buffer_reset(struct pebs_buffer *buf,
		struct perf_output_handle *handle)
{
    //force reset everything
	local_set(&buf->head,0);
    local_set(&buf->lost,0);
    local_set(&buf->data_size,0);

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// START/STOP is not called directly anyway???
static void pebs_event_start(struct perf_event *event, int flags)
{
	struct pebs_ctx *pebs = this_cpu_ptr(&pebs_ctx);
	struct pebs_buffer *buf = perf_get_aux_pebs(&pebs->handle);

	if (!buf)
    {
        WARN(1, "pebs_event_start get aux buffer null???\n");
		return;
    }
	pebs_buffer_reset(buf, &pebs->handle);
    //FIXME! if configuration of ds buffer failed then we should not enabling it
	pebs_config_buffer(buf);
    
    wmb();
	ACCESS_ONCE(pebs->started) = 1;
    x86_pmu_enable(event->pmu);
}

static void pebs_event_stop(struct perf_event *event, int flags)
{
	struct pebs_ctx *pebs = this_cpu_ptr(&pebs_ctx);
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);

#if _DEBUG_
	printk("pebs_event_stop @cpu%d : %s\n",
			smp_processor_id(),
			event->pmu->name);
    dump_events();
#endif
    //disable before recover ds
    x86_pmu_disable(event->pmu);
	recover_ds(pebs, cpuc);

    ACCESS_ONCE(event->hw.state) |= PERF_HES_STOPPED | PERF_HES_UPTODATE;
	ACCESS_ONCE(pebs->started) = 0;
}
///////////////////////////////////////////////////////////////////////////////
/*
 * drain pebs buffer, using aux buffer
 */
int intel_pebs_drain(bool terminate)
{
	struct pebs_ctx *pebs = this_cpu_ptr(&pebs_ctx);
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
	struct perf_event *event;
	struct pebs_buffer *buf;
    struct pebs_phys *phys;
    unsigned long left = 0;
    unsigned int next_buf;

    //FIXME: why not &&?
    //if ((!pebs) || (!ACCESS_ONCE(pebs->started)))
    if ((!pebs) && (!ACCESS_ONCE(pebs->started)))
        return 0;

	if (!x86_pmu.pebs_active)
		return 0;

    if (terminate)
        return 1;

    event = pebs->handle.event;
#if _DEBUG_
	printk("@cpu%d intel_pebs_drain : \n", smp_processor_id());
#endif
	if (!event)
    {
        return 0;
    }

    buf = perf_get_aux_pebs(&pebs->handle);
    if (!buf)
    {
        //already stopped??
        return -2;
    }

    //when will pebs becomes valid?
    if (pebs->valid==0)
    {
        backup_ds(pebs, cpuc);
        goto retry_aux;
    }

	pebs_update(pebs);
	//no data ??
	if (local_read(&buf->data_size)==0)
	{
		return 1;
	}
    if (ACCESS_ONCE(pebs->aux_started))
    {
        //PEBS started and collected data
        phys = &buf->buf[buf->cur_buf];
        left = phys->size - local_read(&buf->data_size);
        //printk("writing %lu bytes, skipping %lu bytes..\n", local_read(&buf->data_size), left);

        perf_aux_output_end_pebs(&pebs->handle, local_xchg(&buf->data_size, 0),
                !!local_xchg(&buf->lost, 0));
        //skip the rest of this buffer
        if (left>0)
        {
	        buf = perf_aux_output_begin_pebs(&pebs->handle, event);
            if (!buf)
            {
                ACCESS_ONCE(pebs->aux_started) = 0;
                //can not skip the rest of the buffer???
                goto retry_aux;
            }
            perf_aux_output_skip_pebs(&pebs->handle, left);
            perf_aux_output_end_pebs(&pebs->handle, 0, 0);
        }else if (left<0)
        {
            BUG();
        }
        ACCESS_ONCE(pebs->aux_started) = 0;
    }
retry_aux:
    if (terminate)
    {
        if (ACCESS_ONCE(pebs->aux_started))
        {
            ACCESS_ONCE(pebs->aux_started) = 0;
            perf_aux_output_end_pebs(&pebs->handle, 0, 0);
        }
        recover_ds(pebs, cpuc);
        return 1;
    }

//FIXME: send dummy perf event to userspace
    struct perf_sample_data data;
    struct pt_regs regs;
    perf_event_overflow(event, &data, &regs);

	buf = perf_aux_output_begin_pebs(&pebs->handle, event);
    ACCESS_ONCE(pebs->aux_started) = 1;
//
//
	if (!buf)
	{
		//WARN(1," (DIE)@cpu%d intel_pebs_drain : buf null? #2\n",
		//		smp_processor_id());
		/*
		 * unable to get free buffer, better luck next time!
		 * program will continue running
		 * record sample lost!
		 */
        ACCESS_ONCE(pebs->aux_started) = 0;
		goto stop_and_err;
	}
    //figure out current buffer
    next_buf = ((pebs->handle.head>>PAGE_SHIFT) % buf->nr_pages)
                    / (buf->nr_pages / buf->nr_bufs);
    buf->cur_buf = next_buf;
	pebs_buffer_reset(buf, &pebs->handle);

    //buf should be fresh. and match 
	pebs_config_buffer(buf);
	return 1;

stop_and_err:
    printk("pebs_interrupt handler error, recover ds\n");
    //dump_events();
    recover_ds(pebs, cpuc);
    //BUG();
	return -1;
}

/*
 * PMI handler
 */
int intel_pebs_interrupt(void)
{
	struct pebs_ctx *pebs = this_cpu_ptr(&pebs_ctx);
    struct perf_event *event = pebs->handle.event;

    if (!event)
        return 0;

#if _DEBUG_
	printk("(@cpu%d) intel_pebs_interrupt(started:?%d) : \n",
			smp_processor_id(),
			pebs->started);
#endif
	if (!ACCESS_ONCE(pebs->started))
		return 0;

	return intel_pebs_drain(false);
}

/*
 * add/del event is used to schedule event?
 */
static void pebs_event_del(struct perf_event *event, int mode)
{
	//call cpu to del this event?
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
	struct pebs_ctx *pebs = this_cpu_ptr(&pebs_ctx);
	struct pebs_buffer *buf = perf_get_aux_pebs(&pebs->handle);

	if (event->attr.type != pebs_pmu.type)
		return;

#if _DEBUG_
	printk("pebs_event_del: @cpu%d: mode %d\n",
			smp_processor_id(),
			mode);
    dump_events();
#endif

	if ((ACCESS_ONCE(pebs->aux_started)==1)
        && (buf!=NULL))
    {
        //printk("pebs_event_del: aux output buf %p\n", buf);
        pebs_update(pebs);
        //perf_aux_output_end_pebs(&pebs->handle, 0, 0);
        perf_aux_output_end_pebs(&pebs->handle, local_xchg(&buf->data_size, 0),
                !!local_xchg(&buf->lost, 0));
    }
    ACCESS_ONCE(pebs->aux_started) = 0;

	/*
	 * call x86_pmu to handler reset of the work
	 * will reset several counter to 0
	 * cpuc->enabled = 0;
	 * cpuc->n_events = 0;
	 * cpuc->n_added = 0;
	 */

	x86_pmu_del(event, mode);

	pebs_event_stop(event, PERF_EF_UPDATE);
    ACCESS_ONCE(pebs->added_event)=0;
}

static int __pebs_event_add(struct perf_event *event, int mode)
{
	struct pebs_ctx *pebs = this_cpu_ptr(&pebs_ctx);
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
	struct pebs_buffer *buf;
//////
    backup_ds(pebs, cpuc);
/////
#if (_DEBUG_ || _DEBUG_DS_)
	printk("backup ds config @cpu%d : [0x%llx,0x%llx] T:0x%llx\n",
			smp_processor_id(),
			pebs->ds_back.pebs_buffer_base,
			pebs->ds_back.pebs_absolute_maximum,
			pebs->ds_back.pebs_interrupt_threshold
			);
#endif
/////
	buf = perf_aux_output_begin_pebs(&pebs->handle, event);

	if (!buf)
    {
        WARN(1, "__pebs_event_add: aux output begin returned NULL?\n");
		return -EINVAL;
    }

    ACCESS_ONCE(pebs->aux_started) = 1;
	
	pebs_buffer_reset(buf, &pebs->handle);
	pebs_config_buffer(buf);

	return 0;
}

static int pebs_event_add(struct perf_event *event, int mode)
{
	int ret;
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
	struct pebs_ctx *pebs = this_cpu_ptr(&pebs_ctx);

	if (event->attr.type != pebs_pmu.type)
		return -ENOENT;
	
#if _DEBUG_
	printk("pebs_event_add: @cpu%d mode 0x%x,"
		" cpuc->enabled: 0x%x"
        " pmu:%s\n",
		smp_processor_id(),
		mode,
		cpuc->enabled,
        event->pmu->name);
#endif

    if (ACCESS_ONCE(pebs->added_event)==1)
    {
        //already added?
        WARN(1, "ALREADY ADDED EVENT!!!\n");
        BUG();
        return 0;
    }

	ret = __pebs_event_add(event, mode);
	if (ret)
	{
#if _DEBUG_
		printk("  (DIE)@cpu%d __pebs_event_add failed!\n",
				smp_processor_id());
#endif
		goto out;
	}
	ret = x86_pmu_add(event, mode);
	if (ret)
	{
		printk("  (DIE)@cpu%d x86_pmu_add failed!\n",
				smp_processor_id());
		goto out;
	}
    ACCESS_ONCE(pebs->added_event)=1;
    /*
     * hw state should be set to stopped and uptodate,
     * x86_pmu_start will examine this bit
     */
    event->hw.state = PERF_HES_STOPPED | PERF_HES_UPTODATE;

	/*
	 * call x86_pmu_enable to enable event
	 * x86_pmu_enable need cpuc->enabled to be 0
	 */
	if (mode & PERF_EF_START)
	{
#if _DEBUG_
		printk("@cpu%d event->hwc.idx=?0x%x,"
			"  cpuc->n_events=%d,"
			"  cpuc->active_mask:%p\n",
				smp_processor_id(),
				event->hw.idx,
				cpuc->n_events,
				cpuc->active_mask);
#endif
        pebs_event_start(event, mode);
	}
out:
#if _DEBUG_
	printk("pebs_event_add: @cpu%d ret=%d(should be 0)\n",
			smp_processor_id(),
			ret);
    dump_events();
#endif

	return ret;
}

static void pebs_event_destroy(struct perf_event *event)
{
	struct pebs_ctx *pebs = this_cpu_ptr(&pebs_ctx);
    x86_del_intel_pebs_usage();
    //should reset this...
    if (ACCESS_ONCE(pebs->aux_started)==1)
    {
        WARN(1, "aux_started should be 0 when destroying event\n");
        pebs_event_del(event, 0);
    }
    ACCESS_ONCE(pebs->aux_started) = 0;
    ACCESS_ONCE(pebs->added_event) = 0;
}

static int pebs_event_init(struct perf_event *event)
{
	int ret;
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
	struct pebs_ctx *pebs = this_cpu_ptr(&pebs_ctx);

	if (event->attr.type != pebs_pmu.type)
		return -ENOENT;

    ACCESS_ONCE(pebs->aux_started) = 0;

#if _DEBUG_
	printk("pebs_event_init : @cpu%d\n", smp_processor_id());
    dump_events();
    if (0)
    {
        union x86_pmu_config *cfg
            = (union x86_pmu_config*)&(event->attr.config);
        printk("...uevent:%d, umask%d\n",cfg->bits.event, cfg->bits.umask);
    }
#endif

	ret = x86_pmu_event_init(event);

    //enable NMI handler here
    x86_add_intel_pebs_usage();
    event->destroy = pebs_event_destroy;

    cpuc->pebs_aux_enabled = 0;

	return ret;
}

static int pebs_pmu_event_idx(struct perf_event *event)
{
	int ret;
	ret = x86_pmu_event_idx(event);
	return ret;
}

static inline void pebs_event_read(struct perf_event *event)
{
}

int is_pebs_event(struct perf_event *event)
{
	return event->pmu == &pebs_pmu;
}

int is_pebs_pmu(struct pmu *pmu)
{
	return pmu == &pebs_pmu;
}

static __init int pebs_init(void)
{
	if (!boot_cpu_has(X86_FEATURE_DTES64) || !x86_pmu.pebs)
		return -ENODEV;

	pebs_pmu.capabilities	= PERF_PMU_CAP_AUX_NO_SG | PERF_PMU_CAP_AUX_SW_DOUBLEBUF;
	pebs_pmu.capabilities	|= PERF_PMU_CAP_EXCLUSIVE;
	pebs_pmu.attr_groups	= x86_pmu_attr_groups;
    //???
	pebs_pmu.task_ctx_nr	= perf_hw_context;

	pebs_pmu.event_init	= pebs_event_init;
	pebs_pmu.add		= pebs_event_add;
	pebs_pmu.del		= pebs_event_del;
	pebs_pmu.read		= pebs_event_read;
	pebs_pmu.start		= pebs_event_start;
	pebs_pmu.stop		= pebs_event_stop;
	pebs_pmu.event_idx	= pebs_pmu_event_idx;
	pebs_pmu.setup_aux	= pebs_buffer_setup_aux;
	pebs_pmu.free_aux	= pebs_buffer_free_aux;

	return perf_pmu_register(&pebs_pmu, "intel_pebs", PERF_TYPE_RAW_PEBS);
}

arch_initcall(pebs_init);

