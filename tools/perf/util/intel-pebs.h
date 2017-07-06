/*
 * PEBSv3+ aux buffer support
 * 2016 Tong Zhang<ztong@vt.edu>
 */
#ifndef INCLUDE__PERF_INTEL_PEBS_H__
#define INCLUDE__PERF_INTEL_PEBS_H__

#define INTEL_PEBS_PMU_NAME "intel_pebs"

#define INTEL_PEBS_AUXTRACE_PRIV_SIZE (INTEL_PEBS_AUXTRACE_PRIV_MAX * sizeof(u64))

enum {
	INTEL_PEBS_PMU_TYPE,
	INTEL_PEBS_TIME_SHIFT,
	INTEL_PEBS_TIME_MULT,
	INTEL_PEBS_TIME_ZERO,
	INTEL_PEBS_CAP_USER_TIME_ZERO,
	INTEL_PEBS_SNAPSHOT_MODE,
	INTEL_PEBS_AUXTRACE_PRIV_MAX,
};

struct auxtrace_record;
struct perf_tool;
union perf_event;
struct perf_session;

struct auxtrace_record *intel_pebs_recording_init(int *err);

int intel_pebs_process_auxtrace_info(union perf_event *event,
				    struct perf_session *session);

#endif
