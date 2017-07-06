/*
 * PEBSv3+ aux data support
 * 2016 Tong Zhang<ztong@vt.edu>
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/log2.h>

#include "../../util/cpumap.h"
#include "../../util/evsel.h"
#include "../../util/evlist.h"
#include "../../util/session.h"
#include "../../util/util.h"
#include "../../util/pmu.h"
#include "../../util/debug.h"
#include "../../util/tsc.h"
#include "../../util/auxtrace.h"
#include "../../util/intel-pebs.h"

#define KiB(x) ((x) * 1024)
#define MiB(x) ((x) * 1024 * 1024)
#define KiB_MASK(x) (KiB(x) - 1)
#define MiB_MASK(x) (MiB(x) - 1)

#define INTEL_PEBS_DFLT_SAMPLE_SIZE	KiB(4)

#define INTEL_PEBS_MAX_SAMPLE_SIZE	KiB(60)

;

struct intel_pebs_recording {
	struct auxtrace_record		itr;
	struct perf_pmu			*intel_pebs_pmu;
	struct perf_evlist		*evlist;
};

static size_t intel_pebs_info_priv_size(struct auxtrace_record *itr __maybe_unused)
{
	return INTEL_PEBS_AUXTRACE_PRIV_SIZE;
}

static int intel_pebs_info_fill(struct auxtrace_record *itr,
			       struct perf_session *session,
			       struct auxtrace_info_event *auxtrace_info,
			       size_t priv_size)
{
	struct intel_pebs_recording *pebsr =
			container_of(itr, struct intel_pebs_recording, itr);
	struct perf_pmu *intel_pebs_pmu = pebsr->intel_pebs_pmu;
	struct perf_event_mmap_page *pc;
	struct perf_tsc_conversion tc = { .time_mult = 0, };
	bool cap_user_time_zero = false;
	int err;

	if (priv_size != INTEL_PEBS_AUXTRACE_PRIV_SIZE)
		return -EINVAL;

	if (!session->evlist->nr_mmaps)
		return -EINVAL;

	pc = session->evlist->mmap[0].base;
	if (pc) {
		err = perf_read_tsc_conversion(pc, &tc);
		if (err) {
			if (err != -EOPNOTSUPP)
				return err;
		} else {
			cap_user_time_zero = tc.time_mult != 0;
		}
		if (!cap_user_time_zero)
			ui__warning("Intel PEBS: TSC not available\n");
	}

	auxtrace_info->type = PERF_AUXTRACE_INTEL_PEBS;
	auxtrace_info->priv[INTEL_PEBS_PMU_TYPE] = intel_pebs_pmu->type;
	auxtrace_info->priv[INTEL_PEBS_TIME_SHIFT] = tc.time_shift;
	auxtrace_info->priv[INTEL_PEBS_TIME_MULT] = tc.time_mult;
	auxtrace_info->priv[INTEL_PEBS_TIME_ZERO] = tc.time_zero;
	auxtrace_info->priv[INTEL_PEBS_CAP_USER_TIME_ZERO] = cap_user_time_zero;

	return 0;
}

static int intel_pebs_recording_options(struct auxtrace_record *itr,
				       struct perf_evlist *evlist,
				       struct record_opts *opts)
{
	struct intel_pebs_recording *pebsr =
			container_of(itr, struct intel_pebs_recording, itr);
	struct perf_pmu *intel_pebs_pmu = pebsr->intel_pebs_pmu;
	struct perf_evsel *evsel, *intel_pebs_evsel = NULL;
	const struct cpu_map *cpus = evlist->cpus;
	//bool privileged = geteuid() == 0 || perf_event_paranoid() < 0;
    
	pebsr->evlist = evlist;

	evlist__for_each(evlist, evsel) {
		if (evsel->attr.type == intel_pebs_pmu->type) {
			if (intel_pebs_evsel) {
				pr_err("There may be only one " INTEL_PEBS_PMU_NAME " event\n");
				return -EINVAL;
			}
			evsel->attr.freq = 0;
			evsel->attr.sample_period = 1;
			intel_pebs_evsel = evsel;
			opts->full_auxtrace = true;
		}
	}

	if (!opts->full_auxtrace)
		return 0;
#if 0
	if (opts->full_auxtrace && !cpu_map__empty(cpus)) {
		pr_err(INTEL_PEBS_PMU_NAME " does not support per-cpu recording\n");
		return -EINVAL;
	}
#endif
#if 0
	/* Set default sizes for full trace mode */
	if (opts->full_auxtrace && !opts->auxtrace_mmap_pages) {
		if (privileged) {
			opts->auxtrace_mmap_pages = MiB(4) / page_size;
		} else {
			opts->auxtrace_mmap_pages = KiB(128) / page_size;
			if (opts->mmap_pages == UINT_MAX)
				opts->mmap_pages = KiB(256) / page_size;
		}
	}
#endif
	/* Validate auxtrace_mmap_pages */
	if (opts->auxtrace_mmap_pages) {
		size_t sz = opts->auxtrace_mmap_pages * (size_t)page_size;
		size_t min_sz;

		min_sz = KiB(8);

		if (sz < min_sz || !is_power_of_2(sz)) {
			pr_err("Invalid mmap size for Intel PEBS: must be at least %zuKiB and a power of 2\n",
			       min_sz / 1024);
			return -EINVAL;
		}
	}

	if (intel_pebs_evsel) {
		/*
		 * To obtain the auxtrace buffer file descriptor, the auxtrace event
		 * must come first.
		 */
		perf_evlist__to_front(evlist, intel_pebs_evsel);
		/*
		 * In the case of per-cpu mmaps, we need the CPU on the
		 * AUX event.
		 */
		if (!cpu_map__empty(cpus))
			perf_evsel__set_sample_bit(intel_pebs_evsel, CPU);
	}

	/* Add dummy event to keep tracking */
	if (opts->full_auxtrace) {
		struct perf_evsel *tracking_evsel;
		int err;

		err = parse_events(evlist, "dummy:u", NULL);
		if (err)
			return err;

		tracking_evsel = perf_evlist__last(evlist);

		perf_evlist__set_tracking_event(evlist, tracking_evsel);

		tracking_evsel->attr.freq = 0;
		tracking_evsel->attr.sample_period = 1;
	}

	return 0;
}

static u64 intel_pebs_reference(struct auxtrace_record *itr __maybe_unused)
{
	return rdtsc();
}

static void intel_pebs_recording_free(struct auxtrace_record *itr)
{
	struct intel_pebs_recording *pebsr =
			container_of(itr, struct intel_pebs_recording, itr);

	free(pebsr);
}

static int intel_pebs_read_finish(struct auxtrace_record *itr, int idx)
{
	struct intel_pebs_recording *pebsr =
			container_of(itr, struct intel_pebs_recording, itr);
	struct perf_evsel *evsel;

	evlist__for_each(pebsr->evlist, evsel) {
		if (evsel->attr.type == pebsr->intel_pebs_pmu->type)
			return perf_evlist__enable_event_idx(pebsr->evlist,
							     evsel, idx);
	}
	return -EINVAL;
}

struct auxtrace_record *intel_pebs_recording_init(int *err)
{
	struct perf_pmu *intel_pebs_pmu = perf_pmu__find(INTEL_PEBS_PMU_NAME);
	struct intel_pebs_recording *pebsr;

	if (!intel_pebs_pmu)
		return NULL;

	pebsr = zalloc(sizeof(struct intel_pebs_recording));
	if (!pebsr) {
		*err = -ENOMEM;
		return NULL;
	}

	pebsr->intel_pebs_pmu = intel_pebs_pmu;
	pebsr->itr.recording_options = intel_pebs_recording_options;
	pebsr->itr.info_priv_size = intel_pebs_info_priv_size;
	pebsr->itr.info_fill = intel_pebs_info_fill;
	pebsr->itr.free = intel_pebs_recording_free;
	pebsr->itr.reference = intel_pebs_reference;
	pebsr->itr.read_finish = intel_pebs_read_finish;
	pebsr->itr.alignment = 0;//????
	return &pebsr->itr;
}
