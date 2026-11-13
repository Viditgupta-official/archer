//! OS process limits. Workers wait on stdin until the parent attaches the limits.
use super::config::Limits;
use std::{
    io,
    process::{Child, Command},
};

#[cfg(windows)]
pub struct ProcessLimits(std::os::windows::io::OwnedHandle);
#[cfg(windows)]
impl ProcessLimits {
    pub fn attach(child: &Child, limits: &Limits) -> io::Result<Self> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::Win32::System::JobObjects::*;
        // The handle is owned exactly once; a failed setup closes it. No source
        // processing can begin while the parent still owns the closed stdin gate.
        unsafe {
            let raw = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if raw.is_null() {
                return Err(io::Error::last_os_error());
            }
            let owned = std::os::windows::io::OwnedHandle::from_raw_handle(raw);
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                | JOB_OBJECT_LIMIT_JOB_MEMORY
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | JOB_OBJECT_LIMIT_PROCESS_TIME
                | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            info.ProcessMemoryLimit = limits.memory_bytes;
            info.JobMemoryLimit = limits.memory_bytes;
            info.BasicLimitInformation.ActiveProcessLimit = 8;
            info.BasicLimitInformation.PerProcessUserTimeLimit =
                ((limits.wall_ms / 1000 + 2) * 10_000_000) as i64;
            if SetInformationJobObject(
                raw,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of_val(&info) as u32,
            ) == 0
                || AssignProcessToJobObject(raw, child.as_raw_handle()) == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(owned))
        }
    }
    pub fn terminate(&self) {
        use std::os::windows::io::AsRawHandle;
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.0.as_raw_handle(), 1);
        }
    }
}
#[cfg(windows)]
pub fn prepare(command: &mut Command, _limits: &Limits) {
    use std::os::windows::process::CommandExt;
    command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
}

#[cfg(target_os = "linux")]
pub struct ProcessLimits(u32);
#[cfg(target_os = "linux")]
impl ProcessLimits {
    pub fn attach(child: &Child, _limits: &Limits) -> io::Result<Self> {
        Ok(Self(child.id()))
    }
    pub fn terminate(&self) {
        unsafe {
            libc::kill(-(self.0 as i32), libc::SIGKILL);
        }
    }
}
#[cfg(target_os = "linux")]
pub fn prepare(command: &mut Command, limits: &Limits) {
    use std::os::unix::process::CommandExt;
    let memory = limits.memory_bytes as libc::rlim_t;
    let cpu = (limits.wall_ms / 1000 + 2) as libc::rlim_t;
    let file = limits
        .result_bytes
        .max(limits.archive_bytes)
        .max(limits.file_bytes) as libc::rlim_t;
    // Only async-signal-safe OS calls occur between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
            {
                return Err(io::Error::last_os_error());
            }
            for (resource, value) in [
                (libc::RLIMIT_AS, memory),
                (libc::RLIMIT_CPU, cpu),
                (libc::RLIMIT_FSIZE, file),
                (libc::RLIMIT_NOFILE, 64),
                (libc::RLIMIT_NPROC, 64),
            ] {
                if libc::setrlimit(
                    resource,
                    &libc::rlimit {
                        rlim_cur: value,
                        rlim_max: value,
                    },
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
pub struct ProcessLimits;
#[cfg(not(any(windows, target_os = "linux")))]
impl ProcessLimits {
    pub fn attach(_: &Child, _: &Limits) -> io::Result<Self> {
        Err(io::Error::other(
            "Resource-limited workers are supported only on Windows and Linux",
        ))
    }
    pub fn terminate(&self) {}
}
#[cfg(not(any(windows, target_os = "linux")))]
pub fn prepare(_: &mut Command, _: &Limits) {}
