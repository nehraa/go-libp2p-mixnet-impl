// Package hub provides a manager-centric receptor layer on top of a single
// libp2p host. A hub owns peer bindings, stream lifecycle, payload events, and
// a dedicated metrics pipeline so one host can safely manage many peer-specific
// receptors on the same listening port.
package hub
