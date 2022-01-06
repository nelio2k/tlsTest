package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var dialer *net.Dialer = &net.Dialer{Timeout: 30 * time.Second}

var options struct {
	rootCertFile string
	clientCertFile string
	clientKeyFile string

	nsServerUrl string
	kvUrl string
}

// Variables to be set after argsParse
var RootCA string
var ClientCert string
var ClientKey string
var NsServerConnStr string
var SslConnStr string

func argParse() {
	flag.StringVar(&options.rootCertFile, "rootCA", "",
		"root CA certificate file path")
	flag.StringVar(&options.clientCertFile, "clientCert", "",
		"client certificate file path")
	flag.StringVar(&options.clientKeyFile, "clientKey", "",
		"client private key file path")


	flag.StringVar(&options.nsServerUrl, "nsServer", "",
		"URL to ns server secure port (i.e. \"127.0.0.1:19001\")")
	flag.StringVar(&options.kvUrl, "kv", "",
		"URL to ns server secure port (i.e. \"127.0.0.1:11994\")")
	flag.Parse()

	RootCA = options.rootCertFile
	ClientKey = options.clientKeyFile
	ClientCert = options.clientCertFile
	NsServerConnStr = options.nsServerUrl
	SslConnStr = options.kvUrl

	if RootCA == "" || ClientCert == "" || ClientKey == "" || NsServerConnStr == "" || SslConnStr == "" {
		fmt.Printf("Required input are missing. Try \"-h\" to see flags\n")
		os.Exit(1)
	}
}

func GetHostName(hostAddr string) string {
	index := strings.LastIndex(hostAddr, ":")
	if index < 0 {
		// host addr does not contain ":". treat host addr as host name
		return hostAddr
	}
	return hostAddr[0:index]
}

func MakeTLSConn(ssl_con_str, username string, certificates []byte, check_server_name bool, clientCertificate, clientKey []byte) (*tls.Conn, *tls.Config, error) {
	if len(certificates) == 0 {
		return nil, nil, fmt.Errorf("No certificate has been provided. Can't establish ssl connection to %v", ssl_con_str)
	}

	// BypassSanInCertificateCheck is by default false
	// In case that some bug in the system prevents ssl connections from being setup because of server name check
	// BypassSanInCertificateCheck can be turned to true to disable server name check and to unblock customer
	check_server_name = true

	// enforce timeout
	errChannel := make(chan error, 2)
	time.AfterFunc(dialer.Timeout, func() {
		errChannel <- errors.New("Exec timeout")
	})

	caPool := x509.NewCertPool()
	ok := caPool.AppendCertsFromPEM(certificates)
	if !ok {
		return nil, nil, errors.New("invalid certificate")
	}

	tlsConfig := &tls.Config{RootCAs: caPool}

	if len(clientCertificate) > 0 {
		clientCert, err := tls.X509KeyPair(clientCertificate, clientKey)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to parse client certificate and client key. err=%v", err)
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}

	// If check_server_name is false, we need to disable server name check during tls handshake to prevent it from failing
	// There is no way to disable just server name check in tls handshake, though.
	// We have to set InsecureSkipVerify to true to disable the entire certificate check during tls handshake
	// We will perform certificate check with server name check disabled after tls handshake
	// If check_server_name is true, there is no need for all these complexities.
	// We can simply set InsecureSkipVerify to false and let tls handshake do all the verifications
	tlsConfig.InsecureSkipVerify = !check_server_name
	hostname := GetHostName(ssl_con_str)
	tlsConfig.ServerName = hostname

	// golang 1.8 added a new curve, X25519, which is not supported by ns_server pre-spock
	// explicitly define curve preferences to get this new curve excluded
	tlsConfig.CurvePreferences = []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.CurveP521}

	// get tcp connection
	rawConn, err := dialer.Dial("tcp", ssl_con_str)

	if err != nil {
		fmt.Printf("Failed to connect to %v, err=%v\n", ssl_con_str, err)
		return nil, nil, err
	}

	tcpConn, ok := rawConn.(*net.TCPConn)
	if !ok {
		// should never get here
		rawConn.Close()
		fmt.Printf("Failed to get tcp connection when connecting to %v\n", ssl_con_str)
		return nil, nil, err
	}

	// always set keep alive
	err = tcpConn.SetKeepAlive(true)
	if err == nil {
		err = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	if err != nil {
		tcpConn.Close()
		fmt.Printf("Failed to set keep alive options when connecting to %v. err=%v\n", ssl_con_str, err)
		return nil, nil, err
	}

	// wrap as tls connection
	tlsConn := tls.Client(tcpConn, tlsConfig)

	// spawn new routine to enforce timeout
	go func() {
		errChannel <- tlsConn.Handshake()
	}()

	err = <-errChannel

	if err != nil {
		tlsConn.Close()
		fmt.Printf("TLS handshake failed when connecting to %v, err=%v\n", ssl_con_str, err)
		return nil, nil, err
	}

	conState := tlsConn.ConnectionState()
	fmt.Printf("DEBUG tlsConn connectionState: HandshakeComplete %v ServerName %v PeerCerts: %v\n",
		conState.HandshakeComplete, conState.ServerName, conState.PeerCertificates)

	if false && len(clientCertificate) > 0 {
		fmt.Printf("DEBUG manual check\n")
		// First get a list of acceptable CAs from the target node cert
		serverCerts := tlsConn.ConnectionState().PeerCertificates
		certPool := x509.NewCertPool()
		// We should only check against index 0
		certPool.AddCert(serverCerts[0])
		acceptableCAs := certPool.Subjects()

		// Now make our client cert a x509 cert
		tlsCert, err := tls.X509KeyPair(clientCertificate, clientKey)
		//return X509KeyPair(certPEMBlock, keyPEMBlock)
		//x509Cert, err := x509.ParseCertificate(clientCertificate)
		if err != nil {
			return nil, nil, err
		}
		x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return nil, nil, err
		}


		var foundACommonCA bool
		for i, ca := range acceptableCAs {
			if bytes.Equal(x509Cert.RawIssuer, ca) {
				fmt.Printf("DEBUG index %v found common CA: %v\n", i, string(ca))
				foundACommonCA = true
			} else {
				fmt.Printf("DEBUG index %v found one non-common CA: %v\n", i, string(ca))
			}
		}

		fmt.Printf("DEBUG manual check found a common CA? %v\n", foundACommonCA)
		if !foundACommonCA {
			return nil, nil, fmt.Errorf("Did not find a common CA between node cert and client cert")
		}
	}

	// If check_server_name is false, certificate check has been disabled during tls handshake
	// Perform additional certificate check here, with server name verification disabled (i.e., with opts.DNSName not set)
	if !check_server_name {
		connState := tlsConn.ConnectionState()
		peer_certs := connState.PeerCertificates

		hasCA := false
		rest := certificates
		var block *pem.Block
		for {
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to parse certificate. err=%v", err)
			}
			if cert.IsCA {
				hasCA = true
				break
			}
		}
		opts := x509.VerifyOptions{
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
		}
		if hasCA {
			opts.Roots = tlsConfig.RootCAs
		}

		for i, cert := range peer_certs {
			if i == 0 {
				continue
			}
			opts.Intermediates.AddCert(cert)
		}
		_, err = peer_certs[0].Verify(opts)
		if err != nil {
			//close the conn
			tlsConn.Close()
			fmt.Printf("TLS Verify failed when connecting to %v, err=%v\n", ssl_con_str, err)
			return nil, nil, err
		}
	}
	return tlsConn, tlsConfig, nil
}



func parseBody(res *http.Response, out interface{}) (err error) {
	if res != nil && res.Body != nil {
		defer res.Body.Close()
		var bod []byte
		if res.ContentLength == 0 {
			// If res.Body is empty, json.Unmarshal on an empty Body will return the error "unexpected end of JSON input"
			// Return a more specific error here so upstream callers can handle it
			err = fmt.Errorf("DNE")
			return
		}
		bod, err = ioutil.ReadAll(io.LimitReader(res.Body, res.ContentLength))
		if err != nil {
			fmt.Printf("Failed to read response body, err=%v\n res=%v\n", err, res)
			return
		}
		fmt.Printf("REST request statuscode %v\n", res.StatusCode)
		if out != nil {
			err = json.Unmarshal(bod, out)
			if err != nil {
				if res.StatusCode == http.StatusNotFound {
					fmt.Printf("Original REST request (%v) received %v response. The URL may be incorrect or requested resource no longer exists", res.Request.URL, string(bod))
				} else {
					fmt.Printf("Failed to unmarshal the response as json, err=%v, bod=%v\n res=%v\n", err, string(bod), res)
				}
				out = bod
				return
			}
		}
	}
	return
}

func testNsServer()  {
	urlStr := fmt.Sprintf("https://%v", NsServerConnStr)
	url, err := url.Parse(urlStr)
	if err != nil {
		panic(err)
	}
	url.Path = "/pools/default"

	httpCommand := "GET"
	var body []byte
	req, err := http.NewRequest(httpCommand, url.String(), bytes.NewBuffer(body))
	if err != nil {
		panic(err)
	}

	certificate, err := ioutil.ReadFile(RootCA)
	if err != nil {
		panic(err)
	}

	clientCert, err := ioutil.ReadFile(ClientCert)
	if err != nil {
		panic(err)
	}

	clientKey, err := ioutil.ReadFile(ClientKey)
	if err != nil {
		panic(err)
	}

	conn, tlsConfig, err := MakeTLSConn(NsServerConnStr, "", certificate, true, clientCert, clientKey)
	if err != nil {
		fmt.Printf("NS_SERVER MakeTLSConn error: %v\n", err)
	}

	if conn != nil {
		fmt.Printf("DEBUG closing connection\n")
		conn.Close()
	}

	var client *http.Client
	tr := &http.Transport{TLSClientConfig: tlsConfig}
	client = &http.Client{Transport: tr,
		Timeout: 30 * time.Second}

	res, err := client.Do(req)
	if err != nil {
		fmt.Printf("Client.Do returned err %v\n", err)
	}

	out := make(map[string]interface{})
	parseErr := parseBody(res, &out)
	if err != nil {
		fmt.Printf("parseErr returned err %v\n", parseErr)
	}

	//fmt.Printf("Ns_Server out: %v\n", out)
	fmt.Printf("DEBUG Ns_server successfull\n")
}


func main() {
	argParse()
	fmt.Printf("DEBUG Testing TLS connection\n")

	certificate, err := ioutil.ReadFile(RootCA)
	if err != nil {
		panic(err)
	}

	clientCert, err := ioutil.ReadFile(ClientCert)
	if err != nil {
		panic(err)
	}

	clientKey, err := ioutil.ReadFile(ClientKey)
	if err != nil {
		panic(err)
	}

	conn, _, err := MakeTLSConn(SslConnStr, "", certificate, true, clientCert, clientKey)
	if err != nil {
		fmt.Printf("MakeTLSConn error: %v\n", err)
	}

	if conn != nil {
		fmt.Printf("DEBUG closing KV connection\n")
		conn.Close()
	}

	fmt.Printf("\nDEBUG Starting ns_server portion...\n")
	testNsServer()
}