//go:build !(cgo && libsignal)

package signal

// openReal is nil in a build without libsignal: Factory returns nil and the
// bridge does not serve Signal (cmd/bridge says so in its log).
var openReal opener
