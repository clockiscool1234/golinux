//go:build windows

package syscalls

// Windows has no poll(2)/select(2) equivalent for arbitrary file
// handles (WSAPoll only covers sockets, and this emulator's pollable
// fds -- stdio and host pipes, see hostFdForFile -- are neither), and
// implementing a real, non-data-consuming readiness check for a pipe
// or console handle needs Windows-specific APIs (PeekNamedPipe and
// friends) this package deliberately doesn't reach for to avoid a new
// platform-specific dependency for one call.
//
// hostPoll instead reports every requested fd immediately ready,
// without actually blocking, regardless of waitMs. That's a
// deliberate, honest approximation, not a bug: the guest program that
// called poll() is about to follow up with a real read()/write() on
// that same fd, and *that* real syscall still blocks correctly (Go's
// os.File.Read on Windows genuinely blocks on a console or pipe with
// no data available) -- so end-to-end behavior for the common case
// (an interactive shell polling stdin before reading a line, or a
// pipeline stage polling a pipe before reading from it) is correct,
// just with the wait happening in the subsequent read() instead of
// here. The one case this doesn't handle well is a guest program that
// sets O_NONBLOCK on a pipe and relies on poll() to avoid ever seeing
// EAGAIN: since hostPoll always claims readiness, such a program could
// busy-loop between poll() and a non-blocking read() that keeps
// returning EAGAIN. That's a known, narrow limitation of running this
// emulator's poll(2)/ppoll(2) support on Windows, not something this
// function can fix without the platform-specific readiness API this
// file deliberately avoids depending on.
func hostPoll(pfds []rawPollFd, waitMs int64) int {
	for i := range pfds {
		pfds[i].revents = pfds[i].events
	}
	return 0
}