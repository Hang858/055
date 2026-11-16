module kemtls-lab

go 1.25.1

require (
	github.com/cloudflare/circl v1.6.3
	pqsig v0.0.0
)

replace pqsig => ../pqsig

require (
	golang.org/x/crypto v0.30.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)
