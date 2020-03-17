diff --git a/Makefile b/Makefile
index ed0499d7..b011f0b3 100644
--- a/Makefile
+++ b/Makefile
@@ -388,3 +388,11 @@ deb:
 	cd $(BUILDDIR) && ./build-package.sh -t oss -v $(VERSION) -p deb -a $(ARCH) $(RUNTIME_SECTION) $(TARBALL_PATH_SECTION)
 	if [ -f e/Makefile ]; then $(MAKE) -C e deb; fi
 
+tpsingle:
+	$(MAKE) $(BUILDDIR)/teleport
+
+tp: tpsingle $(BUILDDIR)/webassets.zip
+	@echo "---> Attaching OSS web assets."
+	cat $(BUILDDIR)/webassets.zip >> $(BUILDDIR)/teleport
+	rm -fr $(BUILDDIR)/webassets.zip
+	zip -q -A $(BUILDDIR)/teleport
\ No newline at end of file
diff --git a/integration/helpers.go b/integration/helpers.go
index da65d0d5..8fa3cd3d 100644
--- a/integration/helpers.go
+++ b/integration/helpers.go
@@ -253,6 +253,8 @@ func (s *InstanceSecrets) GetRoles() []services.Role {
 // case we always return hard-coded userCA + hostCA (and they share keys
 // for simplicity)
 func (s *InstanceSecrets) GetCAs() []services.CertAuthority {
+	log.Error("*** GetCAs")
+
 	hostCA := services.NewCertAuthority(services.HostCA, s.SiteName, [][]byte{s.PrivKey}, [][]byte{s.PubKey}, []string{})
 	hostCA.SetTLSKeyPairs([]services.TLSKeyPair{{Cert: s.TLSCACert, Key: s.PrivKey}})
 	return []services.CertAuthority{
@@ -551,6 +553,8 @@ func (i *TeleInstance) GenerateConfig(trustedSecrets []*InstanceSecrets, tconf *
 // Unlike Create() it allows for greater customization because it accepts
 // a full Teleport config structure
 func (i *TeleInstance) CreateEx(trustedSecrets []*InstanceSecrets, tconf *service.Config) error {
+	log.Error("!!!!CreateEx")
+
 	tconf, err := i.GenerateConfig(trustedSecrets, tconf)
 	if err != nil {
 		return trace.Wrap(err)
@@ -628,6 +632,8 @@ func (i *TeleInstance) CreateEx(trustedSecrets []*InstanceSecrets, tconf *servic
 
 // StartNode starts a SSH node and connects it to the cluster.
 func (i *TeleInstance) StartNode(tconf *service.Config) (*service.TeleportProcess, error) {
+	log.Error("!!!!StartNode")
+
 	dataDir, err := ioutil.TempDir("", "cluster-"+i.Secrets.SiteName)
 	if err != nil {
 		return nil, trace.Wrap(err)
@@ -684,6 +690,8 @@ func (i *TeleInstance) StartNode(tconf *service.Config) (*service.TeleportProces
 // StartNodeAndProxy starts a SSH node and a Proxy Server and connects it to
 // the cluster.
 func (i *TeleInstance) StartNodeAndProxy(name string, sshPort, proxyWebPort, proxySSHPort int) error {
+	log.Error("!!!!StartNodeAndProxy")
+
 	dataDir, err := ioutil.TempDir("", "cluster-"+i.Secrets.SiteName)
 	if err != nil {
 		return trace.Wrap(err)
@@ -765,6 +773,7 @@ type ProxyConfig struct {
 
 // StartProxy starts another Proxy Server and connects it to the cluster.
 func (i *TeleInstance) StartProxy(cfg ProxyConfig) (reversetunnel.Server, error) {
+	log.Error("!!!!StartProxy")
 	dataDir, err := ioutil.TempDir("", "cluster-"+i.Secrets.SiteName+"-"+cfg.Name)
 	if err != nil {
 		return nil, trace.Wrap(err)
@@ -845,6 +854,7 @@ func (i *TeleInstance) StartProxy(cfg ProxyConfig) (reversetunnel.Server, error)
 // Reset re-creates the teleport instance based on the same configuration
 // This is needed if you want to stop the instance, reset it and start again
 func (i *TeleInstance) Reset() (err error) {
+	log.Error("!!!!Reset")
 	i.Process, err = service.NewTeleport(i.Config)
 	if err != nil {
 		return trace.Wrap(err)
diff --git a/lib/auth/apiserver.go b/lib/auth/apiserver.go
index 3a6e5e9b..11df9cf7 100644
--- a/lib/auth/apiserver.go
+++ b/lib/auth/apiserver.go
@@ -153,6 +153,8 @@ func NewAPIServer(config *APIConfig) http.Handler {
 	srv.POST("/:version/tokens/register", srv.withAuth(srv.registerUsingToken))
 	srv.POST("/:version/tokens/register/auth", srv.withAuth(srv.registerNewAuthServer))
 
+	srv.POST("/:version/ibcert/register", srv.withAuth(srv.registerUsingCert))
+
 	// active sesssions
 	srv.POST("/:version/namespaces/:namespace/sessions", srv.withAuth(srv.createSession))
 	srv.PUT("/:version/namespaces/:namespace/sessions/:id", srv.withAuth(srv.updateSession))
@@ -967,6 +969,26 @@ func (s *APIServer) generateToken(auth ClientI, w http.ResponseWriter, r *http.R
 }
 
 func (s *APIServer) registerUsingToken(auth ClientI, w http.ResponseWriter, r *http.Request, _ httprouter.Params, version string) (interface{}, error) {
+	log.Error("!!! API registerUsingToken Cloud")
+
+	var req RegisterUsingTokenRequest
+	if err := httplib.ReadJSON(r, &req); err != nil {
+		return nil, trace.Wrap(err)
+	}
+
+	// Pass along the remote address the request came from to the registration function.
+	req.RemoteAddr = r.RemoteAddr
+
+	keys, err := auth.RegisterUsingToken(req)
+	if err != nil {
+		return nil, trace.Wrap(err)
+	}
+	return keys, nil
+}
+
+func (s *APIServer) registerUsingCert(auth ClientI, w http.ResponseWriter, r *http.Request, _ httprouter.Params, version string) (interface{}, error) {
+	log.Error("!!! API registerUsingToken Cloud")
+
 	var req RegisterUsingTokenRequest
 	if err := httplib.ReadJSON(r, &req); err != nil {
 		return nil, trace.Wrap(err)
diff --git a/lib/auth/auth.go b/lib/auth/auth.go
index 4525a7b5..5272f260 100644
--- a/lib/auth/auth.go
+++ b/lib/auth/auth.go
@@ -62,6 +62,7 @@ type AuthServerOption func(*AuthServer)
 
 // NewAuthServer creates and configures a new AuthServer instance
 func NewAuthServer(cfg *InitConfig, opts ...AuthServerOption) (*AuthServer, error) {
+	log.Errorf("!!! NewAuthServer auth.go %v", cfg.Trust)
 	if cfg.Trust == nil {
 		cfg.Trust = local.NewCAService(cfg.Backend)
 	}
@@ -1131,7 +1132,7 @@ func (r *RegisterUsingTokenRequest) CheckAndSetDefaults() error {
 // after a successful registration.
 func (s *AuthServer) RegisterUsingToken(req RegisterUsingTokenRequest) (*PackedKeys, error) {
 	log.Infof("Node %q [%v] is trying to join with role: %v.", req.NodeName, req.HostID, req.Role)
-
+	log.Errorf("!!! Cloud RegisterUsingToken %v %v %v", string(req.PublicTLSKey), req.HostID, req.Token)
 	if err := req.CheckAndSetDefaults(); err != nil {
 		return nil, trace.Wrap(err)
 	}
@@ -1165,6 +1166,57 @@ func (s *AuthServer) RegisterUsingToken(req RegisterUsingTokenRequest) (*PackedK
 		return nil, trace.Wrap(err)
 	}
 	log.Infof("Node %q [%v] has joined the cluster.", req.NodeName, req.HostID)
+
+	log.Errorf("!!!! keys.Cert %v", string(keys.Cert))
+	log.Errorf("!!!! keys.Key %v", string(keys.Key))
+	for i, cacert := range keys.SSHCACerts {
+		log.Errorf("!!!! %d keys.SSHCACerts %v", i, string(cacert))
+
+	}
+	for i, catlscert := range keys.TLSCACerts {
+		log.Errorf("!!!! %d keys.TLSCACerts %v", i, string(catlscert))
+
+	}
+	log.Errorf("!!!! keys.TLSCert %v", string(keys.TLSCert))
+
+	return keys, nil
+}
+
+func (s *AuthServer) RegisterUsingCert(req RegisterUsingTokenRequest) (*PackedKeys, error) {
+	log.Infof("Node %q [%v] is trying to join with role: %v.", req.NodeName, req.HostID, req.Role)
+	log.Errorf("!!! Cloud RegisterUsingToken %v %v %v", string(req.PublicTLSKey), req.HostID, req.Token)
+	if err := req.CheckAndSetDefaults(); err != nil {
+		return nil, trace.Wrap(err)
+	}
+
+	// generate and return host certificate and keys
+	keys, err := s.GenerateServerKeys(GenerateServerKeysRequest{
+		HostID:               req.HostID,
+		NodeName:             req.NodeName,
+		Roles:                teleport.Roles{req.Role},
+		AdditionalPrincipals: req.AdditionalPrincipals,
+		PublicTLSKey:         req.PublicTLSKey,
+		PublicSSHKey:         req.PublicSSHKey,
+		RemoteAddr:           req.RemoteAddr,
+		DNSNames:             req.DNSNames,
+	})
+	if err != nil {
+		return nil, trace.Wrap(err)
+	}
+	log.Infof("Node %q [%v] has joined the cluster.", req.NodeName, req.HostID)
+
+	log.Errorf("!!!! keys.Cert %v", string(keys.Cert))
+	log.Errorf("!!!! keys.Key %v", string(keys.Key))
+	for i, cacert := range keys.SSHCACerts {
+		log.Errorf("!!!! %d keys.SSHCACerts %v", i, string(cacert))
+
+	}
+	for i, catlscert := range keys.TLSCACerts {
+		log.Errorf("!!!! %d keys.TLSCACerts %v", i, string(catlscert))
+
+	}
+	log.Errorf("!!!! keys.TLSCert %v", string(keys.TLSCert))
+
 	return keys, nil
 }
 
diff --git a/lib/auth/auth_with_roles.go b/lib/auth/auth_with_roles.go
index 58d3ed2e..45da0b28 100644
--- a/lib/auth/auth_with_roles.go
+++ b/lib/auth/auth_with_roles.go
@@ -318,6 +318,11 @@ func (a *AuthWithRoles) RegisterUsingToken(req RegisterUsingTokenRequest) (*Pack
 	return a.authServer.RegisterUsingToken(req)
 }
 
+func (a *AuthWithRoles) RegisterUsingCert(req RegisterUsingTokenRequest) (*PackedKeys, error) {
+	// tokens have authz mechanism  on their own, no need to check
+	return a.authServer.RegisterUsingCert(req)
+}
+
 func (a *AuthWithRoles) RegisterNewAuthServer(token string) error {
 	// tokens have authz mechanism  on their own, no need to check
 	return a.authServer.RegisterNewAuthServer(token)
diff --git a/lib/auth/clt.go b/lib/auth/clt.go
index b4d29130..e5575d79 100644
--- a/lib/auth/clt.go
+++ b/lib/auth/clt.go
@@ -618,10 +618,33 @@ func (c *Client) GenerateToken(req GenerateTokenRequest) (string, error) {
 // RegisterUsingToken calls the auth service API to register a new node using a registration token
 // which was previously issued via GenerateToken.
 func (c *Client) RegisterUsingToken(req RegisterUsingTokenRequest) (*PackedKeys, error) {
+	log.Error("!!! RegisterUsingToken client")
 	if err := req.CheckAndSetDefaults(); err != nil {
 		return nil, trace.Wrap(err)
 	}
-	out, err := c.PostJSON(c.Endpoint("tokens", "register"), req)
+	log.Error("!!! POSTJSON client")
+
+	out, err := c.PostJSON(c.Endpoint("ibcert", "register!!! Register - registerThroughAuth"), req)
+	if err != nil {
+		return nil, trace.Wrap(err)
+	}
+	var keys PackedKeys
+	if err := json.Unmarshal(out.Bytes(), &keys); err != nil {
+		return nil, trace.Wrap(err)
+	}
+	return &keys, nil
+}
+
+// RegisterUsingToken calls the auth service API to register a new node using a registration token
+// which was previously issued via GenerateToken.
+func (c *Client) RegisterUsingCert(req RegisterUsingTokenRequest) (*PackedKeys, error) {
+	log.Error("!!! RegisterUsingCert client")
+	if err := req.CheckAndSetDefaults(); err != nil {
+		return nil, trace.Wrap(err)
+	}
+	log.Error("!!! POSTJSON client")
+
+	out, err := c.PostJSON(c.Endpoint("ibcert", "register"), req)
 	if err != nil {
 		return nil, trace.Wrap(err)
 	}
@@ -2811,6 +2834,10 @@ type ProvisioningService interface {
 	// which has been previously issued via GenerateToken
 	RegisterUsingToken(req RegisterUsingTokenRequest) (*PackedKeys, error)
 
+	// RegisterUsingToken calls the auth service API to register a new node via registration token
+	// which has been previously issued via GenerateToken
+	RegisterUsingCert(req RegisterUsingTokenRequest) (*PackedKeys, error)
+
 	// RegisterNewAuthServer is used to register new auth server with token
 	RegisterNewAuthServer(token string) error
 }
diff --git a/lib/auth/github.go b/lib/auth/github.go
index e3fc86dd..81678800 100644
--- a/lib/auth/github.go
+++ b/lib/auth/github.go
@@ -38,6 +38,7 @@ import (
 
 // CreateGithubAuthRequest creates a new request for Github OAuth2 flow
 func (s *AuthServer) CreateGithubAuthRequest(req services.GithubAuthRequest) (*services.GithubAuthRequest, error) {
+	log.Error("!!! CreateGithubAuthRequest")
 	connector, err := s.Identity.GetGithubConnector(req.ConnectorID, true)
 	if err != nil {
 		return nil, trace.Wrap(err)
diff --git a/lib/auth/init.go b/lib/auth/init.go
index 0340c174..e30670bc 100644
--- a/lib/auth/init.go
+++ b/lib/auth/init.go
@@ -23,7 +23,9 @@ import (
 	"crypto/x509"
 	"crypto/x509/pkix"
 	"fmt"
+	"io/ioutil"
 	"net"
+	"path/filepath"
 	"strings"
 	"time"
 
@@ -142,6 +144,8 @@ type InitConfig struct {
 
 // Init instantiates and configures an instance of AuthServer
 func Init(cfg InitConfig, opts ...AuthServerOption) (*AuthServer, error) {
+	log.Error("!!! Init CA")
+
 	if cfg.DataDir == "" {
 		return nil, trace.BadParameter("DataDir: data dir can not be empty")
 	}
@@ -157,6 +161,7 @@ func Init(cfg InitConfig, opts ...AuthServerOption) (*AuthServer, error) {
 	defer backend.ReleaseLock(context.TODO(), cfg.Backend, domainName)
 
 	// check that user CA and host CA are present and set the certs if needed
+	log.Error("!!! create NewAuthServer - asrv, user CA and host CA")
 	asrv, err := NewAuthServer(&cfg, opts...)
 	if err != nil {
 		return nil, trace.Wrap(err)
@@ -194,7 +199,10 @@ func Init(cfg InitConfig, opts ...AuthServerOption) (*AuthServer, error) {
 		}
 		log.Infof("Created role: %v.", role)
 	}
+
+	log.Errorf("!!! asrv.Trust.CreateCertAuthority if exist in cfg")
 	for i := range cfg.Authorities {
+		log.Errorf("*** cfg.Authorities[%d] [%v]", i, cfg.Authorities[i])
 		ca := cfg.Authorities[i]
 		ca, err = services.GetCertAuthorityMarshaler().GenerateCertAuthority(ca)
 		if err != nil {
@@ -293,6 +301,7 @@ func Init(cfg InitConfig, opts ...AuthServerOption) (*AuthServer, error) {
 		log.Infof("Created default admin role: %q.", defaultRole.GetName())
 	}
 
+	log.Errorf("!!! generate a user certificate authority if it doesn't exist")
 	// generate a user certificate authority if it doesn't exist
 	userCA, err := asrv.GetCertAuthority(services.CertAuthID{DomainName: cfg.ClusterName.GetClusterName(), Type: services.UserCA}, true)
 	if err != nil {
@@ -348,6 +357,7 @@ func Init(cfg InitConfig, opts ...AuthServerOption) (*AuthServer, error) {
 		}
 	}
 
+	log.Errorf("!!! asrv.GetCertAuthority host")
 	// generate a host certificate authority if it doesn't exist
 	hostCA, err := asrv.GetCertAuthority(services.CertAuthID{DomainName: cfg.ClusterName.GetClusterName(), Type: services.HostCA}, true)
 	if err != nil {
@@ -356,11 +366,13 @@ func Init(cfg InitConfig, opts ...AuthServerOption) (*AuthServer, error) {
 		}
 
 		log.Infof("First start: generating host certificate authority.")
+
 		priv, pub, err := asrv.GenerateKeyPair("")
 		if err != nil {
 			return nil, trace.Wrap(err)
 		}
 
+		///generate cert
 		keyPEM, certPEM, err := tlsca.GenerateSelfSignedCA(pkix.Name{
 			CommonName:   cfg.ClusterName.GetClusterName(),
 			Organization: []string{cfg.ClusterName.GetClusterName()},
@@ -368,6 +380,28 @@ func Init(cfg InitConfig, opts ...AuthServerOption) (*AuthServer, error) {
 		if err != nil {
 			return nil, trace.Wrap(err)
 		}
+		path := filepath.Join(cfg.DataDir, "CA.key")
+		err = ioutil.WriteFile(path, keyPEM, 0777)
+		if err != nil {
+			fmt.Println(err)
+		}
+
+		path = filepath.Join(cfg.DataDir, "CA.crt")
+		err = ioutil.WriteFile(path, certPEM, 0777)
+		if err != nil {
+			fmt.Println(err)
+		}
+		path = filepath.Join(cfg.DataDir, "publ.key")
+		err = ioutil.WriteFile(path, pub, 0777)
+		if err != nil {
+			fmt.Println(err)
+		}
+		path = filepath.Join(cfg.DataDir, "priv.key")
+		err = ioutil.WriteFile(path, priv, 0777)
+		if err != nil {
+			fmt.Println(err)
+		}
+
 		hostCA = &services.CertAuthorityV2{
 			Kind:    services.KindCertAuthority,
 			Version: services.V2,
diff --git a/lib/auth/middleware.go b/lib/auth/middleware.go
index 7ca09d61..199363b5 100644
--- a/lib/auth/middleware.go
+++ b/lib/auth/middleware.go
@@ -133,6 +133,12 @@ func (t *TLSServer) Serve(listener net.Listener) error {
 // and server's GetConfigForClient reloads the list of trusted
 // local and remote certificate authorities
 func (t *TLSServer) GetConfigForClient(info *tls.ClientHelloInfo) (*tls.Config, error) {
+
+	// if _, err := os.Stat("debug"); !os.IsNotExist(err) {
+	// 	panic("!GetConfigForClient")
+	// }
+	log.Errorf("!!! GetConfigForClient: %#v", *info)
+
 	var clusterName string
 	var err error
 	if info.ServerName != "" {
@@ -161,8 +167,9 @@ func (t *TLSServer) GetConfigForClient(info *tls.ClientHelloInfo) (*tls.Config,
 	}
 	tlsCopy := t.TLS.Clone()
 	tlsCopy.ClientCAs = pool
-	for _, cert := range tlsCopy.Certificates {
+	for idx, cert := range tlsCopy.Certificates {
 		t.Debugf("Server certificate %v.", TLSCertInfo(&cert))
+		t.Errorf("!!! Server certificate %d", idx)
 	}
 	return tlsCopy, nil
 }
@@ -318,6 +325,7 @@ func (a *AuthMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
 
 // ClientCertPool returns trusted x509 cerificate authority pool
 func ClientCertPool(client AccessCache, clusterName string) (*x509.CertPool, error) {
+	log.Errorf("!!! returns trusted x509 cerificate authority pool")
 	pool := x509.NewCertPool()
 	var authorities []services.CertAuthority
 	if clusterName == "" {
@@ -348,14 +356,15 @@ func ClientCertPool(client AccessCache, clusterName string) (*x509.CertPool, err
 		authorities = append(authorities, userCA)
 	}
 
-	for _, auth := range authorities {
-		for _, keyPair := range auth.GetTLSKeyPairs() {
+	for idx, auth := range authorities {
+		for idx2, keyPair := range auth.GetTLSKeyPairs() {
 			cert, err := tlsca.ParseCertificatePEM(keyPair.Cert)
 			if err != nil {
 				return nil, trace.Wrap(err)
 			}
 			log.Debugf("ClientCertPool -> %v", CertInfo(cert))
 			pool.AddCert(cert)
+			log.Errorf("ClientCertPool -> %d, %d", idx, idx2)
 		}
 	}
 	return pool, nil
diff --git a/lib/auth/register.go b/lib/auth/register.go
index 7f766b00..8995723c 100644
--- a/lib/auth/register.go
+++ b/lib/auth/register.go
@@ -111,6 +111,7 @@ func Register(params RegisterParams) (*Identity, error) {
 
 	// Attempt to register through the auth server, if it fails, try and
 	// register through the proxy server.
+	log.Errorf("!!! Register - registerThroughAuth")
 	ident, err := registerThroughAuth(token, params)
 	if err != nil {
 		// If no params client was set this is a proxy and fail right away.
@@ -163,7 +164,7 @@ func registerThroughProxy(token string, params RegisterParams) (*Identity, error
 
 // registerThroughAuth is used to register through the auth server.
 func registerThroughAuth(token string, params RegisterParams) (*Identity, error) {
-	log.Debugf("Attempting to register through auth server.")
+	log.Error("Attempting to register through auth server. *Cert*")
 
 	var client *Client
 	var err error
@@ -183,7 +184,7 @@ func registerThroughAuth(token string, params RegisterParams) (*Identity, error)
 	defer client.Close()
 
 	// Get the SSH and X509 certificates for a node.
-	keys, err := client.RegisterUsingToken(RegisterUsingTokenRequest{
+	keys, err := client.RegisterUsingCert(RegisterUsingTokenRequest{
 		Token:                token,
 		HostID:               params.ID.HostUUID,
 		NodeName:             params.ID.NodeName,
@@ -258,6 +259,7 @@ func readCA(params RegisterParams) (*x509.Certificate, error) {
 // validate the certificate presented. If both conditions hold true, then we
 // know we are connecting to the expected Auth Server.
 func pinRegisterClient(params RegisterParams) (*Client, error) {
+	log.Error("**** pinRegisterClient")
 	// Build a insecure client to the Auth Server. This is safe because even if
 	// an attacker were to MITM this connection the CA pin will not match below.
 	tlsConfig := utils.TLSConfig(params.CipherSuites)
diff --git a/lib/cache/cache.go b/lib/cache/cache.go
index 8aabec26..c9a51277 100644
--- a/lib/cache/cache.go
+++ b/lib/cache/cache.go
@@ -262,6 +262,7 @@ func New(config Config) (*Cache, error) {
 		return nil, trace.Wrap(err)
 	}
 	wrapper := backend.NewWrapper(config.Backend)
+	log.Errorf("!!! New %v", config)
 	ctx, cancel := context.WithCancel(config.Context)
 	cs := &Cache{
 		wrapper:            wrapper,
diff --git a/lib/config/configuration.go b/lib/config/configuration.go
index c3963098..610bf04e 100644
--- a/lib/config/configuration.go
+++ b/lib/config/configuration.go
@@ -213,16 +213,6 @@ func ApplyFileConfig(fc *FileConfig, cfg *service.Config) error {
 		}
 
 		cfg.Auth.StorageConfig = fc.Storage
-		// backend is specified, but no path is set, set a reasonable default
-		_, pathSet := cfg.Auth.StorageConfig.Params[defaults.BackendPath]
-		if cfg.Auth.StorageConfig.Type == lite.GetName() && !pathSet {
-			if cfg.Auth.StorageConfig.Params == nil {
-				cfg.Auth.StorageConfig.Params = make(backend.Params)
-			}
-			cfg.Auth.StorageConfig.Params[defaults.BackendPath] = filepath.Join(cfg.DataDir, defaults.BackendDir)
-		}
-	} else {
-		// Set a reasonable default.
 		cfg.Auth.StorageConfig.Params[defaults.BackendPath] = filepath.Join(cfg.DataDir, defaults.BackendDir)
 	}
 
diff --git a/lib/service/connect.go b/lib/service/connect.go
index d8b95a6a..47c579ca 100644
--- a/lib/service/connect.go
+++ b/lib/service/connect.go
@@ -85,6 +85,7 @@ func (process *TeleportProcess) connectToAuthService(role teleport.Role) (*Conne
 }
 
 func (process *TeleportProcess) connect(role teleport.Role) (conn *Connector, err error) {
+	log.Errorf("!!! connect")
 	state, err := process.storage.GetState(role)
 	if err != nil {
 		if !trace.IsNotFound(err) {
@@ -124,6 +125,8 @@ func (process *TeleportProcess) connect(role teleport.Role) (conn *Connector, er
 			}, nil
 		}
 		log.Infof("Connecting to the cluster %v with TLS client certificate.", identity.ClusterName)
+
+		log.Errorf("!Identity: cert%v tlsca%v tls%v", string(*&identity.CertBytes), string(*&identity.TLSCACertsBytes[0]), string(*&identity.TLSCertBytes))
 		client, err := process.newClient(process.Config.AuthServers, identity)
 		if err != nil {
 			return nil, trace.Wrap(err)
@@ -351,6 +354,8 @@ func (process *TeleportProcess) firstTimeConnect(role teleport.Role) (*Connector
 			return nil, trace.Wrap(err)
 		}
 
+		log.Errorf("keyPair.PrivateKey %v", string(keyPair.PrivateKey))
+		log.Errorf("keyPair.PublicTLSKey %v", string(keyPair.PublicTLSKey))
 		identity, err = auth.Register(auth.RegisterParams{
 			DataDir:              process.Config.DataDir,
 			Token:                process.Config.Token,
@@ -373,6 +378,11 @@ func (process *TeleportProcess) firstTimeConnect(role teleport.Role) (*Connector
 	}
 
 	log.Infof("%v has obtained credentials to connect to cluster.", role)
+
+	log.Errorf("identity.TLSCertBytes %v", string(identity.TLSCertBytes))
+	log.Errorf("identity.KeyBytes %v", string(identity.KeyBytes))
+	log.Errorf("identity.TLSCACertsBytes %v", string(identity.TLSCACertsBytes[0]))
+
 	var connector *Connector
 	if role == teleport.RoleAdmin || role == teleport.RoleAuth {
 		connector = &Connector{
diff --git a/lib/service/service.go b/lib/service/service.go
index 250a38bd..ddfe4267 100644
--- a/lib/service/service.go
+++ b/lib/service/service.go
@@ -388,6 +388,7 @@ type Process interface {
 type NewProcess func(cfg *Config) (Process, error)
 
 func newTeleportProcess(cfg *Config) (Process, error) {
+	log.Error("!!! NewTeleport")
 	return NewTeleport(cfg)
 }
 
@@ -900,6 +901,7 @@ func initExternalLog(auditConfig services.AuditConfig) (events.IAuditLog, error)
 
 // initAuthService can be called to initialize auth server service
 func (process *TeleportProcess) initAuthService() error {
+
 	var err error
 
 	cfg := process.Config
@@ -965,33 +967,34 @@ func (process *TeleportProcess) initAuthService() error {
 			return trace.Wrap(err)
 		}
 	}
-
+	log.Error("!!! first, create the AuthServer")
 	// first, create the AuthServer
 	authServer, err := auth.Init(auth.InitConfig{
-		Backend:              b,
-		Authority:            cfg.Keygen,
-		ClusterConfiguration: cfg.ClusterConfiguration,
-		ClusterConfig:        cfg.Auth.ClusterConfig,
-		ClusterName:          cfg.Auth.ClusterName,
-		AuthServiceName:      cfg.Hostname,
-		DataDir:              cfg.DataDir,
-		HostUUID:             cfg.HostUUID,
-		NodeName:             cfg.Hostname,
-		Authorities:          cfg.Auth.Authorities,
-		Resources:            cfg.Auth.Resources,
-		ReverseTunnels:       cfg.ReverseTunnels,
-		Trust:                cfg.Trust,
-		Presence:             cfg.Presence,
-		Events:               cfg.Events,
-		Provisioner:          cfg.Provisioner,
-		Identity:             cfg.Identity,
-		Access:               cfg.Access,
-		StaticTokens:         cfg.Auth.StaticTokens,
-		Roles:                cfg.Auth.Roles,
-		AuthPreference:       cfg.Auth.Preference,
-		OIDCConnectors:       cfg.OIDCConnectors,
-		AuditLog:             process.auditLog,
-		CipherSuites:         cfg.CipherSuites,
+		Backend:                b,
+		Authority:              cfg.Keygen,
+		ClusterConfiguration:   cfg.ClusterConfiguration,
+		ClusterConfig:          cfg.Auth.ClusterConfig,
+		ClusterName:            cfg.Auth.ClusterName,
+		AuthServiceName:        cfg.Hostname,
+		DataDir:                cfg.DataDir,
+		HostUUID:               cfg.HostUUID,
+		NodeName:               cfg.Hostname,
+		Authorities:            cfg.Auth.Authorities,
+		Resources:              cfg.Auth.Resources,
+		ReverseTunnels:         cfg.ReverseTunnels,
+		Trust:                  cfg.Trust,
+		Presence:               cfg.Presence,
+		Events:                 cfg.Events,
+		Provisioner:            cfg.Provisioner,
+		Identity:               cfg.Identity,
+		Access:                 cfg.Access,
+		StaticTokens:           cfg.Auth.StaticTokens,
+		Roles:                  cfg.Auth.Roles,
+		AuthPreference:         cfg.Auth.Preference,
+		OIDCConnectors:         cfg.OIDCConnectors,
+		AuditLog:               process.auditLog,
+		CipherSuites:           cfg.CipherSuites,
+		SkipPeriodicOperations: true,
 	})
 	if err != nil {
 		return trace.Wrap(err)
@@ -1080,6 +1083,8 @@ func (process *TeleportProcess) initAuthService() error {
 		return trace.Wrap(err)
 	}
 	go mux.Serve()
+	log.Error("!!!Starting Auth service with PROXY protocol support.")
+
 	process.RegisterCriticalFunc("auth.tls", func() error {
 		utils.Consolef(cfg.Console, teleport.ComponentAuth, "Auth service %s:%s is starting on %v.", teleport.Version, teleport.Gitref, cfg.Auth.SSHAddr.Addr)
 
diff --git a/lib/services/local/trust.go b/lib/services/local/trust.go
index a72db81c..6f7ca604 100644
--- a/lib/services/local/trust.go
+++ b/lib/services/local/trust.go
@@ -3,12 +3,18 @@ package local
 import (
 	"context"
 
+	"github.com/gravitational/teleport"
 	"github.com/gravitational/teleport/lib/backend"
 	"github.com/gravitational/teleport/lib/services"
+	"github.com/sirupsen/logrus"
 
 	"github.com/gravitational/trace"
 )
 
+var log = logrus.WithFields(logrus.Fields{
+	trace.Component: teleport.ComponentAuth,
+})
+
 // CA is local implementation of Trust service that
 // is using local backend
 type CA struct {
@@ -17,6 +23,7 @@ type CA struct {
 
 // NewCAService returns new instance of CAService
 func NewCAService(b backend.Backend) *CA {
+	log.Error("*** NewCAService")
 	return &CA{
 		Backend: b,
 	}
@@ -30,6 +37,7 @@ func (s *CA) DeleteAllCertAuthorities(caType services.CertAuthType) error {
 
 // CreateCertAuthority updates or inserts a new certificate authority
 func (s *CA) CreateCertAuthority(ca services.CertAuthority) error {
+	log.Error("*** CreateCertAuthority")
 	if err := ca.Check(); err != nil {
 		return trace.Wrap(err)
 	}
@@ -55,13 +63,18 @@ func (s *CA) CreateCertAuthority(ca services.CertAuthority) error {
 
 // UpsertCertAuthority updates or inserts a new certificate authority
 func (s *CA) UpsertCertAuthority(ca services.CertAuthority) error {
+	log.Error("*** UpsertCertAuthority")
 	if err := ca.Check(); err != nil {
 		return trace.Wrap(err)
 	}
-	value, err := services.GetCertAuthorityMarshaler().MarshalCertAuthority(ca)
+
+	cam := services.GetCertAuthorityMarshaler()
+
+	value, err := cam.MarshalCertAuthority(ca)
 	if err != nil {
 		return trace.Wrap(err)
 	}
+	log.Error("!!!PUT Key Trust ", authoritiesPrefix, string(ca.GetType()), ca.GetName())
 	item := backend.Item{
 		Key:     backend.Key(authoritiesPrefix, string(ca.GetType()), ca.GetName()),
 		Value:   value,
@@ -115,6 +128,7 @@ func (s *CA) CompareAndSwapCertAuthority(new, existing services.CertAuthority) e
 
 // DeleteCertAuthority deletes particular certificate authority
 func (s *CA) DeleteCertAuthority(id services.CertAuthID) error {
+	log.Error("*** DeleteCertAuthority")
 	if err := id.Check(); err != nil {
 		return trace.Wrap(err)
 	}
@@ -201,13 +215,18 @@ func (s *CA) DeactivateCertAuthority(id services.CertAuthID) error {
 // GetCertAuthority returns certificate authority by given id. Parameter loadSigningKeys
 // controls if signing keys are loaded
 func (s *CA) GetCertAuthority(id services.CertAuthID, loadSigningKeys bool, opts ...services.MarshalOption) (services.CertAuthority, error) {
+	log.Errorf("*** GetCertAuthority 1%v", id)
 	if err := id.Check(); err != nil {
 		return nil, trace.Wrap(err)
 	}
+
 	item, err := s.Get(context.TODO(), backend.Key(authoritiesPrefix, string(id.Type), id.DomainName))
 	if err != nil {
+		log.Error("Get Trust Key1 err ", string(id.Type), id.DomainName, err)
 		return nil, trace.Wrap(err)
 	}
+	log.Error("Get Trust Key2 ", string(id.Type), id.DomainName, err)
+
 	ca, err := services.GetCertAuthorityMarshaler().UnmarshalCertAuthority(
 		item.Value, services.AddOptions(opts, services.WithResourceID(item.ID), services.WithExpires(item.Expires))...)
 	if err != nil {
diff --git a/lib/tlsca/ca.go b/lib/tlsca/ca.go
index 26cca14a..5d70997d 100644
--- a/lib/tlsca/ca.go
+++ b/lib/tlsca/ca.go
@@ -193,6 +193,7 @@ func (ca *CertAuthority) GenerateCertificate(req CertificateRequest) ([]byte, er
 		"org":         req.Subject.Organization,
 		"org_unit":    req.Subject.OrganizationalUnit,
 		"locality":    req.Subject.Locality,
+		"CertCA":      string(ca.Cert.Signature),
 	}).Infof("Generating TLS certificate %v.", req)
 
 	template := &x509.Certificate{
@@ -222,6 +223,6 @@ func (ca *CertAuthority) GenerateCertificate(req CertificateRequest) ([]byte, er
 	if err != nil {
 		return nil, trace.Wrap(err)
 	}
-
+	log.Errorf("!!! certBytes %s", string(certBytes))
 	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}), nil
 }
diff --git a/lib/web/apiserver.go b/lib/web/apiserver.go
index c8d94585..0c40feef 100644
--- a/lib/web/apiserver.go
+++ b/lib/web/apiserver.go
@@ -1867,7 +1867,7 @@ func (h *Handler) hostCredentials(w http.ResponseWriter, r *http.Request, p http
 	if err := httplib.ReadJSON(r, &req); err != nil {
 		return nil, trace.Wrap(err)
 	}
-
+	log.Error("!!!!! hostCredentials req %v", req)
 	authClient := h.cfg.ProxyClient
 	packedKeys, err := authClient.RegisterUsingToken(req)
 	if err != nil {
diff --git a/lib/web/static.go b/lib/web/static.go
index 82d4a4c9..fb57b3aa 100644
--- a/lib/web/static.go
+++ b/lib/web/static.go
@@ -62,6 +62,8 @@ func NewStaticFileSystem(debugMode bool) (http.FileSystem, error) {
 			debugAssetsPath = path.Join(exePath, "../web/dist")
 		}
 
+		debugAssetsPath = "/home/dlahuta/repos/teleport/web/dist"
+
 		for _, af := range assetsToCheck {
 			_, err := os.Stat(filepath.Join(debugAssetsPath, af))
 			if err != nil {
diff --git a/tool/teleport/common/teleport.go b/tool/teleport/common/teleport.go
index 9dea02c7..deaa7c2c 100644
--- a/tool/teleport/common/teleport.go
+++ b/tool/teleport/common/teleport.go
@@ -48,7 +48,7 @@ type Options struct {
 }
 
 // Run inits/starts the process according to the provided options
-func Run(options Options) (executedCommand string, conf *service.Config) {
+func Run(options Options, cfg *service.Config) (executedCommand string, conf *service.Config) {
 	var err error
 
 	// configure trace's errors to produce full stack traces
@@ -147,7 +147,11 @@ func Run(options Options) (executedCommand string, conf *service.Config) {
 	}
 
 	// Create default configuration.
-	conf = service.MakeDefaultConfig()
+	if cfg != nil {
+		conf = cfg
+	} else {
+		conf = service.MakeDefaultConfig()
+	}
 
 	// If FIPS mode is specified update defaults to be FIPS appropriate.
 	if ccf.FIPS {
@@ -185,6 +189,7 @@ func Run(options Options) (executedCommand string, conf *service.Config) {
 
 // OnStart is the handler for "start" CLI command
 func OnStart(config *service.Config) error {
+	log.Error("!! OnStart")
 	return service.Run(context.TODO(), *config, nil)
 }
 
diff --git a/tool/teleport/main.go b/tool/teleport/main.go
index 35fa11a8..79c407e6 100644
--- a/tool/teleport/main.go
+++ b/tool/teleport/main.go
@@ -17,13 +17,84 @@ limitations under the License.
 package main
 
 import (
+	"context"
+	"fmt"
 	"os"
 
+	"github.com/gravitational/teleport/lib/backend"
+	"github.com/gravitational/teleport/lib/backend/lite"
+	"github.com/gravitational/teleport/lib/service"
+	"github.com/gravitational/teleport/lib/services/local"
 	"github.com/gravitational/teleport/tool/teleport/common"
 )
 
 func main() {
+	_, cfg := common.Run(common.Options{
+		Args:     os.Args[1:],
+		InitOnly: true,
+	}, nil)
+
+	//	cfg := service.MakeDefaultConfig()
+
+	// bc := &process.Config.Auth.StorageConfig
+
+	bk, err := lite.New(context.TODO(), cfg.Auth.StorageConfig.Params)
+	if err != nil {
+		panic(fmt.Errorf("No config in backend on start: %s", err))
+	}
+	//cfg.Trust = local.NewCAService(bk)
+	cfg.Trust = NewMyCAService(bk, cfg).CA
+
+	// precomputeCount := native.PrecomputedNum
+	// // in case if not auth or proxy services are enabled,
+	// // there is no need to precompute any SSH keys in the pool
+	// if !cfg.Auth.Enabled && !cfg.Proxy.Enabled {
+	// 	precomputeCount = 0
+	// }
+	// if cfg.Keygen, err = native.New(context.TODO(), native.PrecomputeKeys(precomputeCount)); err != nil {
+	// 	panic(fmt.Errorf("Error on keygen alt creation: %s", err))
+	// }
+
 	common.Run(common.Options{
 		Args: os.Args[1:],
-	})
+	}, cfg)
+
+	// p, err := service.NewTeleport(cfg)
+
+	// authServer := p.GetAuthServer()
+	// authServer.Trust = NewMyCAService(p.GetBackend(), cfg)
+
+	// fmt.Println("err:", err)
+	// p.Run()
+}
+
+//MyCA ..
+type MyCA struct {
+	*local.CA
 }
+
+//NewMyCAService ..
+func NewMyCAService(b backend.Backend, config *service.Config) *MyCA {
+	bk, err := lite.New(context.TODO(), config.Auth.StorageConfig.Params)
+	if err != nil {
+		panic(fmt.Errorf("No config in backend on start: %s", err))
+	}
+
+	return &MyCA{
+		CA: local.NewCAService(bk),
+	}
+}
+
+/*
+type CA struct {
+	backend.Backend
+}
+
+// NewCAService returns new instance of CAService
+func NewCAService(b backend.Backend) *CA {
+	log.Error("*** NewCAService")
+	return &CA{
+		Backend: b,
+	}
+}
+*/
diff --git a/Makefile b/Makefile
index ed0499d7..b011f0b3 100644
--- a/Makefile
+++ b/Makefile
@@ -388,3 +388,11 @@ deb:
 	cd $(BUILDDIR) && ./build-package.sh -t oss -v $(VERSION) -p deb -a $(ARCH) $(RUNTIME_SECTION) $(TARBALL_PATH_SECTION)
 	if [ -f e/Makefile ]; then $(MAKE) -C e deb; fi
 
+tpsingle:
+	$(MAKE) $(BUILDDIR)/teleport
+
+tp: tpsingle $(BUILDDIR)/webassets.zip
+	@echo "---> Attaching OSS web assets."
+	cat $(BUILDDIR)/webassets.zip >> $(BUILDDIR)/teleport
+	rm -fr $(BUILDDIR)/webassets.zip
+	zip -q -A $(BUILDDIR)/teleport
\ No newline at end of file
diff --git a/integration/helpers.go b/integration/helpers.go
index da65d0d5..8fa3cd3d 100644
--- a/integration/helpers.go
+++ b/integration/helpers.go
@@ -253,6 +253,8 @@ func (s *InstanceSecrets) GetRoles() []services.Role {
 // case we always return hard-coded userCA + hostCA (and they share keys
 // for simplicity)
 func (s *InstanceSecrets) GetCAs() []services.CertAuthority {
+	log.Error("*** GetCAs")
+
 	hostCA := services.NewCertAuthority(services.HostCA, s.SiteName, [][]byte{s.PrivKey}, [][]byte{s.PubKey}, []string{})
 	hostCA.SetTLSKeyPairs([]services.TLSKeyPair{{Cert: s.TLSCACert, Key: s.PrivKey}})
 	return []services.CertAuthority{
@@ -551,6 +553,8 @@ func (i *TeleInstance) GenerateConfig(trustedSecrets []*InstanceSecrets, tconf *
 // Unlike Create() it allows for greater customization because it accepts
 // a full Teleport config structure
 func (i *TeleInstance) CreateEx(trustedSecrets []*InstanceSecrets, tconf *service.Config) error {
+	log.Error("!!!!CreateEx")
+
 	tconf, err := i.GenerateConfig(trustedSecrets, tconf)
 	if err != nil {
 		return trace.Wrap(err)
@@ -628,6 +632,8 @@ func (i *TeleInstance) CreateEx(trustedSecrets []*InstanceSecrets, tconf *servic
 
 // StartNode starts a SSH node and connects it to the cluster.
 func (i *TeleInstance) StartNode(tconf *service.Config) (*service.TeleportProcess, error) {
+	log.Error("!!!!StartNode")
+
 	dataDir, err := ioutil.TempDir("", "cluster-"+i.Secrets.SiteName)
 	if err != nil {
 		return nil, trace.Wrap(err)
@@ -684,6 +690,8 @@ func (i *TeleInstance) StartNode(tconf *service.Config) (*service.TeleportProces
 // StartNodeAndProxy starts a SSH node and a Proxy Server and connects it to
 // the cluster.
 func (i *TeleInstance) StartNodeAndProxy(name string, sshPort, proxyWebPort, proxySSHPort int) error {
+	log.Error("!!!!StartNodeAndProxy")
+
 	dataDir, err := ioutil.TempDir("", "cluster-"+i.Secrets.SiteName)
 	if err != nil {
 		return trace.Wrap(err)
@@ -765,6 +773,7 @@ type ProxyConfig struct {
 
 // StartProxy starts another Proxy Server and connects it to the cluster.
 func (i *TeleInstance) StartProxy(cfg ProxyConfig) (reversetunnel.Server, error) {
+	log.Error("!!!!StartProxy")
 	dataDir, err := ioutil.TempDir("", "cluster-"+i.Secrets.SiteName+"-"+cfg.Name)
 	if err != nil {
 		return nil, trace.Wrap(err)
@@ -845,6 +854,7 @@ func (i *TeleInstance) StartProxy(cfg ProxyConfig) (reversetunnel.Server, error)
 // Reset re-creates the teleport instance based on the same configuration
 // This is needed if you want to stop the instance, reset it and start again
 func (i *TeleInstance) Reset() (err error) {
+	log.Error("!!!!Reset")
 	i.Process, err = service.NewTeleport(i.Config)
 	if err != nil {
 		return trace.Wrap(err)
diff --git a/lib/auth/apiserver.go b/lib/auth/apiserver.go
index 3a6e5e9b..11df9cf7 100644
--- a/lib/auth/apiserver.go
+++ b/lib/auth/apiserver.go
@@ -153,6 +153,8 @@ func NewAPIServer(config *APIConfig) http.Handler {
 	srv.POST("/:version/tokens/register", srv.withAuth(srv.registerUsingToken))
 	srv.POST("/:version/tokens/register/auth", srv.withAuth(srv.registerNewAuthServer))
 
+	srv.POST("/:version/ibcert/register", srv.withAuth(srv.registerUsingCert))
+
 	// active sesssions
 	srv.POST("/:version/namespaces/:namespace/sessions", srv.withAuth(srv.createSession))
 	srv.PUT("/:version/namespaces/:namespace/sessions/:id", srv.withAuth(srv.updateSession))
@@ -967,6 +969,26 @@ func (s *APIServer) generateToken(auth ClientI, w http.ResponseWriter, r *http.R
 }
 
 func (s *APIServer) registerUsingToken(auth ClientI, w http.ResponseWriter, r *http.Request, _ httprouter.Params, version string) (interface{}, error) {
+	log.Error("!!! API registerUsingToken Cloud")
+
+	var req RegisterUsingTokenRequest
+	if err := httplib.ReadJSON(r, &req); err != nil {
+		return nil, trace.Wrap(err)
+	}
+
+	// Pass along the remote address the request came from to the registration function.
+	req.RemoteAddr = r.RemoteAddr
+
+	keys, err := auth.RegisterUsingToken(req)
+	if err != nil {
+		return nil, trace.Wrap(err)
+	}
+	return keys, nil
+}
+
+func (s *APIServer) registerUsingCert(auth ClientI, w http.ResponseWriter, r *http.Request, _ httprouter.Params, version string) (interface{}, error) {
+	log.Error("!!! API registerUsingToken Cloud")
+
 	var req RegisterUsingTokenRequest
 	if err := httplib.ReadJSON(r, &req); err != nil {
 		return nil, trace.Wrap(err)
diff --git a/lib/auth/auth.go b/lib/auth/auth.go
index 4525a7b5..5272f260 100644
--- a/lib/auth/auth.go
+++ b/lib/auth/auth.go
@@ -62,6 +62,7 @@ type AuthServerOption func(*AuthServer)
 
 // NewAuthServer creates and configures a new AuthServer instance
 func NewAuthServer(cfg *InitConfig, opts ...AuthServerOption) (*AuthServer, error) {
+	log.Errorf("!!! NewAuthServer auth.go %v", cfg.Trust)
 	if cfg.Trust == nil {
 		cfg.Trust = local.NewCAService(cfg.Backend)
 	}
@@ -1131,7 +1132,7 @@ func (r *RegisterUsingTokenRequest) CheckAndSetDefaults() error {
 // after a successful registration.
 func (s *AuthServer) RegisterUsingToken(req RegisterUsingTokenRequest) (*PackedKeys, error) {
 	log.Infof("Node %q [%v] is trying to join with role: %v.", req.NodeName, req.HostID, req.Role)
-
+	log.Errorf("!!! Cloud RegisterUsingToken %v %v %v", string(req.PublicTLSKey), req.HostID, req.Token)
 	if err := req.CheckAndSetDefaults(); err != nil {
 		return nil, trace.Wrap(err)
 	}
@@ -1165,6 +1166,57 @@ func (s *AuthServer) RegisterUsingToken(req RegisterUsingTokenRequest) (*PackedK
 		return nil, trace.Wrap(err)
 	}
 	log.Infof("Node %q [%v] has joined the cluster.", req.NodeName, req.HostID)
+
+	log.Errorf("!!!! keys.Cert %v", string(keys.Cert))
+	log.Errorf("!!!! keys.Key %v", string(keys.Key))
+	for i, cacert := range keys.SSHCACerts {
+		log.Errorf("!!!! %d keys.SSHCACerts %v", i, string(cacert))
+
+	}
+	for i, catlscert := range keys.TLSCACerts {
+		log.Errorf("!!!! %d keys.TLSCACerts %v", i, string(catlscert))
+
+	}
+	log.Errorf("!!!! keys.TLSCert %v", string(keys.TLSCert))
+
+	return keys, nil
+}
+
+func (s *AuthServer) RegisterUsingCert(req RegisterUsingTokenRequest) (*PackedKeys, error) {
+	log.Infof("Node %q [%v] is trying to join with role: %v.", req.NodeName, req.HostID, req.Role)
+	log.Errorf("!!! Cloud RegisterUsingToken %v %v %v", string(req.PublicTLSKey), req.HostID, req.Token)
+	if err := req.CheckAndSetDefaults(); err != nil {
+		return nil, trace.Wrap(err)
+	}
+
+	// generate and return host certificate and keys
+	keys, err := s.GenerateServerKeys(GenerateServerKeysRequest{
+		HostID:               req.HostID,
+		NodeName:             req.NodeName,
+		Roles:                teleport.Roles{req.Role},
+		AdditionalPrincipals: req.AdditionalPrincipals,
+		PublicTLSKey:         req.PublicTLSKey,
+		PublicSSHKey:         req.PublicSSHKey,
+		RemoteAddr:           req.RemoteAddr,
+		DNSNames:             req.DNSNames,
+	})
+	if err != nil {
+		return nil, trace.Wrap(err)
+	}
+	log.Infof("Node %q [%v] has joined the cluster.", req.NodeName, req.HostID)
+
+	log.Errorf("!!!! keys.Cert %v", string(keys.Cert))
+	log.Errorf("!!!! keys.Key %v", string(keys.Key))
+	for i, cacert := range keys.SSHCACerts {
+		log.Errorf("!!!! %d keys.SSHCACerts %v", i, string(cacert))
+
+	}
+	for i, catlscert := range keys.TLSCACerts {
+		log.Errorf("!!!! %d keys.TLSCACerts %v", i, string(catlscert))
+
+	}
+	log.Errorf("!!!! keys.TLSCert %v", string(keys.TLSCert))
+
 	return keys, nil
 }
 
diff --git a/lib/auth/auth_with_roles.go b/lib/auth/auth_with_roles.go
index 58d3ed2e..45da0b28 100644
--- a/lib/auth/auth_with_roles.go
+++ b/lib/auth/auth_with_roles.go
@@ -318,6 +318,11 @@ func (a *AuthWithRoles) RegisterUsingToken(req RegisterUsingTokenRequest) (*Pack
 	return a.authServer.RegisterUsingToken(req)
 }
 
+func (a *AuthWithRoles) RegisterUsingCert(req RegisterUsingTokenRequest) (*PackedKeys, error) {
+	// tokens have authz mechanism  on their own, no need to check
+	return a.authServer.RegisterUsingCert(req)
+}
+
 func (a *AuthWithRoles) RegisterNewAuthServer(token string) error {
 	// tokens have authz mechanism  on their own, no need to check
 	return a.authServer.RegisterNewAuthServer(token)
diff --git a/lib/auth/clt.go b/lib/auth/clt.go
index b4d29130..e5575d79 100644
--- a/lib/auth/clt.go
+++ b/lib/auth/clt.go
@@ -618,10 +618,33 @@ func (c *Client) GenerateToken(req GenerateTokenRequest) (string, error) {
 // RegisterUsingToken calls the auth service API to register a new node using a registration token
 // which was previously issued via GenerateToken.
 func (c *Client) RegisterUsingToken(req RegisterUsingTokenRequest) (*PackedKeys, error) {
+	log.Error("!!! RegisterUsingToken client")
 	if err := req.CheckAndSetDefaults(); err != nil {
 		return nil, trace.Wrap(err)
 	}
-	out, err := c.PostJSON(c.Endpoint("tokens", "register"), req)
+	log.Error("!!! POSTJSON client")
+
+	out, err := c.PostJSON(c.Endpoint("ibcert", "register!!! Register - registerThroughAuth"), req)
+	if err != nil {
+		return nil, trace.Wrap(err)
+	}
+	var keys PackedKeys
+	if err := json.Unmarshal(out.Bytes(), &keys); err != nil {
+		return nil, trace.Wrap(err)
+	}
+	return &keys, nil
+}
+
+// RegisterUsingToken calls the auth service API to register a new node using a registration token
+// which was previously issued via GenerateToken.
+func (c *Client) RegisterUsingCert(req RegisterUsingTokenRequest) (*PackedKeys, error) {
+	log.Error("!!! RegisterUsingCert client")
+	if err := req.CheckAndSetDefaults(); err != nil {
+		return nil, trace.Wrap(err)
+	}
+	log.Error("!!! POSTJSON client")
+
+	out, err := c.PostJSON(c.Endpoint("ibcert", "register"), req)
 	if err != nil {
 		return nil, trace.Wrap(err)
 	}
@@ -2811,6 +2834,10 @@ type ProvisioningService interface {
 	// which has been previously issued via GenerateToken
 	RegisterUsingToken(req RegisterUsingTokenRequest) (*PackedKeys, error)
 
+	// RegisterUsingToken calls the auth service API to register a new node via registration token
+	// which has been previously issued via GenerateToken
+	RegisterUsingCert(req RegisterUsingTokenRequest) (*PackedKeys, error)
+
 	// RegisterNewAuthServer is used to register new auth server with token
 	RegisterNewAuthServer(token string) error
 }
diff --git a/lib/auth/github.go b/lib/auth/github.go
index e3fc86dd..81678800 100644
--- a/lib/auth/github.go
+++ b/lib/auth/github.go
@@ -38,6 +38,7 @@ import (
 
 // CreateGithubAuthRequest creates a new request for Github OAuth2 flow
 func (s *AuthServer) CreateGithubAuthRequest(req services.GithubAuthRequest) (*services.GithubAuthRequest, error) {
+	log.Error("!!! CreateGithubAuthRequest")
 	connector, err := s.Identity.GetGithubConnector(req.ConnectorID, true)
 	if err != nil {
 		return nil, trace.Wrap(err)
diff --git a/lib/auth/init.go b/lib/auth/init.go
index 0340c174..e30670bc 100644
--- a/lib/auth/init.go
+++ b/lib/auth/init.go
@@ -23,7 +23,9 @@ import (
 	"crypto/x509"
 	"crypto/x509/pkix"
 	"fmt"
+	"io/ioutil"
 	"net"
+	"path/filepath"
 	"strings"
 	"time"
 
@@ -142,6 +144,8 @@ type InitConfig struct {
 
 // Init instantiates and configures an instance of AuthServer
 func Init(cfg InitConfig, opts ...AuthServerOption) (*AuthServer, error) {
+	log.Error("!!! Init CA")
+
 	if cfg.DataDir == "" {
 		return nil, trace.BadParameter("DataDir: data dir can not be empty")
 	}
@@ -157,6 +161,7 @@ func Init(cfg InitConfig, opts ...AuthServerOption) (*AuthServer, error) {
 	defer backend.ReleaseLock(context.TODO(), cfg.Backend, domainName)
 
 	// check that user CA and host CA are present and set the certs if needed
+	log.Error("!!! create NewAuthServer - asrv, user CA and host CA")
 	asrv, err := NewAuthServer(&cfg, opts...)
 	if err != nil {
 		return nil, trace.Wrap(err)
@@ -194,7 +199,10 @@ func Init(cfg InitConfig, opts ...AuthServerOption) (*AuthServer, error) {
 		}
 		log.Infof("Created role: %v.", role)
 	}
+
+	log.Errorf("!!! asrv.Trust.CreateCertAuthority if exist in cfg")
 	for i := range cfg.Authorities {
+		log.Errorf("*** cfg.Authorities[%d] [%v]", i, cfg.Authorities[i])
 		ca := cfg.Authorities[i]
 		ca, err = services.GetCertAuthorityMarshaler().GenerateCertAuthority(ca)
 		if err != nil {
@@ -293,6 +301,7 @@ func Init(cfg InitConfig, opts ...AuthServerOption) (*AuthServer, error) {
 		log.Infof("Created default admin role: %q.", defaultRole.GetName())
 	}
 
+	log.Errorf("!!! generate a user certificate authority if it doesn't exist")
 	// generate a user certificate authority if it doesn't exist
 	userCA, err := asrv.GetCertAuthority(services.CertAuthID{DomainName: cfg.ClusterName.GetClusterName(), Type: services.UserCA}, true)
 	if err != nil {
@@ -348,6 +357,7 @@ func Init(cfg InitConfig, opts ...AuthServerOption) (*AuthServer, error) {
 		}
 	}
 
+	log.Errorf("!!! asrv.GetCertAuthority host")
 	// generate a host certificate authority if it doesn't exist
 	hostCA, err := asrv.GetCertAuthority(services.CertAuthID{DomainName: cfg.ClusterName.GetClusterName(), Type: services.HostCA}, true)
 	if err != nil {
@@ -356,11 +366,13 @@ func Init(cfg InitConfig, opts ...AuthServerOption) (*AuthServer, error) {
 		}
 
 		log.Infof("First start: generating host certificate authority.")
+
 		priv, pub, err := asrv.GenerateKeyPair("")
 		if err != nil {
 			return nil, trace.Wrap(err)
 		}
 
+		///generate cert
 		keyPEM, certPEM, err := tlsca.GenerateSelfSignedCA(pkix.Name{
 			CommonName:   cfg.ClusterName.GetClusterName(),
 			Organization: []string{cfg.ClusterName.GetClusterName()},
@@ -368,6 +380,28 @@ func Init(cfg InitConfig, opts ...AuthServerOption) (*AuthServer, error) {
 		if err != nil {
 			return nil, trace.Wrap(err)
 		}
+		path := filepath.Join(cfg.DataDir, "CA.key")
+		err = ioutil.WriteFile(path, keyPEM, 0777)
+		if err != nil {
+			fmt.Println(err)
+		}
+
+		path = filepath.Join(cfg.DataDir, "CA.crt")
+		err = ioutil.WriteFile(path, certPEM, 0777)
+		if err != nil {
+			fmt.Println(err)
+		}
+		path = filepath.Join(cfg.DataDir, "publ.key")
+		err = ioutil.WriteFile(path, pub, 0777)
+		if err != nil {
+			fmt.Println(err)
+		}
+		path = filepath.Join(cfg.DataDir, "priv.key")
+		err = ioutil.WriteFile(path, priv, 0777)
+		if err != nil {
+			fmt.Println(err)
+		}
+
 		hostCA = &services.CertAuthorityV2{
 			Kind:    services.KindCertAuthority,
 			Version: services.V2,
diff --git a/lib/auth/middleware.go b/lib/auth/middleware.go
index 7ca09d61..199363b5 100644
--- a/lib/auth/middleware.go
+++ b/lib/auth/middleware.go
@@ -133,6 +133,12 @@ func (t *TLSServer) Serve(listener net.Listener) error {
 // and server's GetConfigForClient reloads the list of trusted
 // local and remote certificate authorities
 func (t *TLSServer) GetConfigForClient(info *tls.ClientHelloInfo) (*tls.Config, error) {
+
+	// if _, err := os.Stat("debug"); !os.IsNotExist(err) {
+	// 	panic("!GetConfigForClient")
+	// }
+	log.Errorf("!!! GetConfigForClient: %#v", *info)
+
 	var clusterName string
 	var err error
 	if info.ServerName != "" {
@@ -161,8 +167,9 @@ func (t *TLSServer) GetConfigForClient(info *tls.ClientHelloInfo) (*tls.Config,
 	}
 	tlsCopy := t.TLS.Clone()
 	tlsCopy.ClientCAs = pool
-	for _, cert := range tlsCopy.Certificates {
+	for idx, cert := range tlsCopy.Certificates {
 		t.Debugf("Server certificate %v.", TLSCertInfo(&cert))
+		t.Errorf("!!! Server certificate %d", idx)
 	}
 	return tlsCopy, nil
 }
@@ -318,6 +325,7 @@ func (a *AuthMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
 
 // ClientCertPool returns trusted x509 cerificate authority pool
 func ClientCertPool(client AccessCache, clusterName string) (*x509.CertPool, error) {
+	log.Errorf("!!! returns trusted x509 cerificate authority pool")
 	pool := x509.NewCertPool()
 	var authorities []services.CertAuthority
 	if clusterName == "" {
@@ -348,14 +356,15 @@ func ClientCertPool(client AccessCache, clusterName string) (*x509.CertPool, err
 		authorities = append(authorities, userCA)
 	}
 
-	for _, auth := range authorities {
-		for _, keyPair := range auth.GetTLSKeyPairs() {
+	for idx, auth := range authorities {
+		for idx2, keyPair := range auth.GetTLSKeyPairs() {
 			cert, err := tlsca.ParseCertificatePEM(keyPair.Cert)
 			if err != nil {
 				return nil, trace.Wrap(err)
 			}
 			log.Debugf("ClientCertPool -> %v", CertInfo(cert))
 			pool.AddCert(cert)
+			log.Errorf("ClientCertPool -> %d, %d", idx, idx2)
 		}
 	}
 	return pool, nil
diff --git a/lib/auth/register.go b/lib/auth/register.go
index 7f766b00..8995723c 100644
--- a/lib/auth/register.go
+++ b/lib/auth/register.go
@@ -111,6 +111,7 @@ func Register(params RegisterParams) (*Identity, error) {
 
 	// Attempt to register through the auth server, if it fails, try and
 	// register through the proxy server.
+	log.Errorf("!!! Register - registerThroughAuth")
 	ident, err := registerThroughAuth(token, params)
 	if err != nil {
 		// If no params client was set this is a proxy and fail right away.
@@ -163,7 +164,7 @@ func registerThroughProxy(token string, params RegisterParams) (*Identity, error
 
 // registerThroughAuth is used to register through the auth server.
 func registerThroughAuth(token string, params RegisterParams) (*Identity, error) {
-	log.Debugf("Attempting to register through auth server.")
+	log.Error("Attempting to register through auth server. *Cert*")
 
 	var client *Client
 	var err error
@@ -183,7 +184,7 @@ func registerThroughAuth(token string, params RegisterParams) (*Identity, error)
 	defer client.Close()
 
 	// Get the SSH and X509 certificates for a node.
-	keys, err := client.RegisterUsingToken(RegisterUsingTokenRequest{
+	keys, err := client.RegisterUsingCert(RegisterUsingTokenRequest{
 		Token:                token,
 		HostID:               params.ID.HostUUID,
 		NodeName:             params.ID.NodeName,
@@ -258,6 +259,7 @@ func readCA(params RegisterParams) (*x509.Certificate, error) {
 // validate the certificate presented. If both conditions hold true, then we
 // know we are connecting to the expected Auth Server.
 func pinRegisterClient(params RegisterParams) (*Client, error) {
+	log.Error("**** pinRegisterClient")
 	// Build a insecure client to the Auth Server. This is safe because even if
 	// an attacker were to MITM this connection the CA pin will not match below.
 	tlsConfig := utils.TLSConfig(params.CipherSuites)
diff --git a/lib/cache/cache.go b/lib/cache/cache.go
index 8aabec26..c9a51277 100644
--- a/lib/cache/cache.go
+++ b/lib/cache/cache.go
@@ -262,6 +262,7 @@ func New(config Config) (*Cache, error) {
 		return nil, trace.Wrap(err)
 	}
 	wrapper := backend.NewWrapper(config.Backend)
+	log.Errorf("!!! New %v", config)
 	ctx, cancel := context.WithCancel(config.Context)
 	cs := &Cache{
 		wrapper:            wrapper,
diff --git a/lib/config/configuration.go b/lib/config/configuration.go
index c3963098..610bf04e 100644
--- a/lib/config/configuration.go
+++ b/lib/config/configuration.go
@@ -213,16 +213,6 @@ func ApplyFileConfig(fc *FileConfig, cfg *service.Config) error {
 		}
 
 		cfg.Auth.StorageConfig = fc.Storage
-		// backend is specified, but no path is set, set a reasonable default
-		_, pathSet := cfg.Auth.StorageConfig.Params[defaults.BackendPath]
-		if cfg.Auth.StorageConfig.Type == lite.GetName() && !pathSet {
-			if cfg.Auth.StorageConfig.Params == nil {
-				cfg.Auth.StorageConfig.Params = make(backend.Params)
-			}
-			cfg.Auth.StorageConfig.Params[defaults.BackendPath] = filepath.Join(cfg.DataDir, defaults.BackendDir)
-		}
-	} else {
-		// Set a reasonable default.
 		cfg.Auth.StorageConfig.Params[defaults.BackendPath] = filepath.Join(cfg.DataDir, defaults.BackendDir)
 	}
 
diff --git a/lib/service/connect.go b/lib/service/connect.go
index d8b95a6a..47c579ca 100644
--- a/lib/service/connect.go
+++ b/lib/service/connect.go
@@ -85,6 +85,7 @@ func (process *TeleportProcess) connectToAuthService(role teleport.Role) (*Conne
 }
 
 func (process *TeleportProcess) connect(role teleport.Role) (conn *Connector, err error) {
+	log.Errorf("!!! connect")
 	state, err := process.storage.GetState(role)
 	if err != nil {
 		if !trace.IsNotFound(err) {
@@ -124,6 +125,8 @@ func (process *TeleportProcess) connect(role teleport.Role) (conn *Connector, er
 			}, nil
 		}
 		log.Infof("Connecting to the cluster %v with TLS client certificate.", identity.ClusterName)
+
+		log.Errorf("!Identity: cert%v tlsca%v tls%v", string(*&identity.CertBytes), string(*&identity.TLSCACertsBytes[0]), string(*&identity.TLSCertBytes))
 		client, err := process.newClient(process.Config.AuthServers, identity)
 		if err != nil {
 			return nil, trace.Wrap(err)
@@ -351,6 +354,8 @@ func (process *TeleportProcess) firstTimeConnect(role teleport.Role) (*Connector
 			return nil, trace.Wrap(err)
 		}
 
+		log.Errorf("keyPair.PrivateKey %v", string(keyPair.PrivateKey))
+		log.Errorf("keyPair.PublicTLSKey %v", string(keyPair.PublicTLSKey))
 		identity, err = auth.Register(auth.RegisterParams{
 			DataDir:              process.Config.DataDir,
 			Token:                process.Config.Token,
@@ -373,6 +378,11 @@ func (process *TeleportProcess) firstTimeConnect(role teleport.Role) (*Connector
 	}
 
 	log.Infof("%v has obtained credentials to connect to cluster.", role)
+
+	log.Errorf("identity.TLSCertBytes %v", string(identity.TLSCertBytes))
+	log.Errorf("identity.KeyBytes %v", string(identity.KeyBytes))
+	log.Errorf("identity.TLSCACertsBytes %v", string(identity.TLSCACertsBytes[0]))
+
 	var connector *Connector
 	if role == teleport.RoleAdmin || role == teleport.RoleAuth {
 		connector = &Connector{
diff --git a/lib/service/service.go b/lib/service/service.go
index 250a38bd..ddfe4267 100644
--- a/lib/service/service.go
+++ b/lib/service/service.go
@@ -388,6 +388,7 @@ type Process interface {
 type NewProcess func(cfg *Config) (Process, error)
 
 func newTeleportProcess(cfg *Config) (Process, error) {
+	log.Error("!!! NewTeleport")
 	return NewTeleport(cfg)
 }
 
@@ -900,6 +901,7 @@ func initExternalLog(auditConfig services.AuditConfig) (events.IAuditLog, error)
 
 // initAuthService can be called to initialize auth server service
 func (process *TeleportProcess) initAuthService() error {
+
 	var err error
 
 	cfg := process.Config
@@ -965,33 +967,34 @@ func (process *TeleportProcess) initAuthService() error {
 			return trace.Wrap(err)
 		}
 	}
-
+	log.Error("!!! first, create the AuthServer")
 	// first, create the AuthServer
 	authServer, err := auth.Init(auth.InitConfig{
-		Backend:              b,
-		Authority:            cfg.Keygen,
-		ClusterConfiguration: cfg.ClusterConfiguration,
-		ClusterConfig:        cfg.Auth.ClusterConfig,
-		ClusterName:          cfg.Auth.ClusterName,
-		AuthServiceName:      cfg.Hostname,
-		DataDir:              cfg.DataDir,
-		HostUUID:             cfg.HostUUID,
-		NodeName:             cfg.Hostname,
-		Authorities:          cfg.Auth.Authorities,
-		Resources:            cfg.Auth.Resources,
-		ReverseTunnels:       cfg.ReverseTunnels,
-		Trust:                cfg.Trust,
-		Presence:             cfg.Presence,
-		Events:               cfg.Events,
-		Provisioner:          cfg.Provisioner,
-		Identity:             cfg.Identity,
-		Access:               cfg.Access,
-		StaticTokens:         cfg.Auth.StaticTokens,
-		Roles:                cfg.Auth.Roles,
-		AuthPreference:       cfg.Auth.Preference,
-		OIDCConnectors:       cfg.OIDCConnectors,
-		AuditLog:             process.auditLog,
-		CipherSuites:         cfg.CipherSuites,
+		Backend:                b,
+		Authority:              cfg.Keygen,
+		ClusterConfiguration:   cfg.ClusterConfiguration,
+		ClusterConfig:          cfg.Auth.ClusterConfig,
+		ClusterName:            cfg.Auth.ClusterName,
+		AuthServiceName:        cfg.Hostname,
+		DataDir:                cfg.DataDir,
+		HostUUID:               cfg.HostUUID,
+		NodeName:               cfg.Hostname,
+		Authorities:            cfg.Auth.Authorities,
+		Resources:              cfg.Auth.Resources,
+		ReverseTunnels:         cfg.ReverseTunnels,
+		Trust:                  cfg.Trust,
+		Presence:               cfg.Presence,
+		Events:                 cfg.Events,
+		Provisioner:            cfg.Provisioner,
+		Identity:               cfg.Identity,
+		Access:                 cfg.Access,
+		StaticTokens:           cfg.Auth.StaticTokens,
+		Roles:                  cfg.Auth.Roles,
+		AuthPreference:         cfg.Auth.Preference,
+		OIDCConnectors:         cfg.OIDCConnectors,
+		AuditLog:               process.auditLog,
+		CipherSuites:           cfg.CipherSuites,
+		SkipPeriodicOperations: true,
 	})
 	if err != nil {
 		return trace.Wrap(err)
@@ -1080,6 +1083,8 @@ func (process *TeleportProcess) initAuthService() error {
 		return trace.Wrap(err)
 	}
 	go mux.Serve()
+	log.Error("!!!Starting Auth service with PROXY protocol support.")
+
 	process.RegisterCriticalFunc("auth.tls", func() error {
 		utils.Consolef(cfg.Console, teleport.ComponentAuth, "Auth service %s:%s is starting on %v.", teleport.Version, teleport.Gitref, cfg.Auth.SSHAddr.Addr)
 
diff --git a/lib/services/local/trust.go b/lib/services/local/trust.go
index a72db81c..6f7ca604 100644
--- a/lib/services/local/trust.go
+++ b/lib/services/local/trust.go
@@ -3,12 +3,18 @@ package local
 import (
 	"context"
 
+	"github.com/gravitational/teleport"
 	"github.com/gravitational/teleport/lib/backend"
 	"github.com/gravitational/teleport/lib/services"
+	"github.com/sirupsen/logrus"
 
 	"github.com/gravitational/trace"
 )
 
+var log = logrus.WithFields(logrus.Fields{
+	trace.Component: teleport.ComponentAuth,
+})
+
 // CA is local implementation of Trust service that
 // is using local backend
 type CA struct {
@@ -17,6 +23,7 @@ type CA struct {
 
 // NewCAService returns new instance of CAService
 func NewCAService(b backend.Backend) *CA {
+	log.Error("*** NewCAService")
 	return &CA{
 		Backend: b,
 	}
@@ -30,6 +37,7 @@ func (s *CA) DeleteAllCertAuthorities(caType services.CertAuthType) error {
 
 // CreateCertAuthority updates or inserts a new certificate authority
 func (s *CA) CreateCertAuthority(ca services.CertAuthority) error {
+	log.Error("*** CreateCertAuthority")
 	if err := ca.Check(); err != nil {
 		return trace.Wrap(err)
 	}
@@ -55,13 +63,18 @@ func (s *CA) CreateCertAuthority(ca services.CertAuthority) error {
 
 // UpsertCertAuthority updates or inserts a new certificate authority
 func (s *CA) UpsertCertAuthority(ca services.CertAuthority) error {
+	log.Error("*** UpsertCertAuthority")
 	if err := ca.Check(); err != nil {
 		return trace.Wrap(err)
 	}
-	value, err := services.GetCertAuthorityMarshaler().MarshalCertAuthority(ca)
+
+	cam := services.GetCertAuthorityMarshaler()
+
+	value, err := cam.MarshalCertAuthority(ca)
 	if err != nil {
 		return trace.Wrap(err)
 	}
+	log.Error("!!!PUT Key Trust ", authoritiesPrefix, string(ca.GetType()), ca.GetName())
 	item := backend.Item{
 		Key:     backend.Key(authoritiesPrefix, string(ca.GetType()), ca.GetName()),
 		Value:   value,
@@ -115,6 +128,7 @@ func (s *CA) CompareAndSwapCertAuthority(new, existing services.CertAuthority) e
 
 // DeleteCertAuthority deletes particular certificate authority
 func (s *CA) DeleteCertAuthority(id services.CertAuthID) error {
+	log.Error("*** DeleteCertAuthority")
 	if err := id.Check(); err != nil {
 		return trace.Wrap(err)
 	}
@@ -201,13 +215,18 @@ func (s *CA) DeactivateCertAuthority(id services.CertAuthID) error {
 // GetCertAuthority returns certificate authority by given id. Parameter loadSigningKeys
 // controls if signing keys are loaded
 func (s *CA) GetCertAuthority(id services.CertAuthID, loadSigningKeys bool, opts ...services.MarshalOption) (services.CertAuthority, error) {
+	log.Errorf("*** GetCertAuthority 1%v", id)
 	if err := id.Check(); err != nil {
 		return nil, trace.Wrap(err)
 	}
+
 	item, err := s.Get(context.TODO(), backend.Key(authoritiesPrefix, string(id.Type), id.DomainName))
 	if err != nil {
+		log.Error("Get Trust Key1 err ", string(id.Type), id.DomainName, err)
 		return nil, trace.Wrap(err)
 	}
+	log.Error("Get Trust Key2 ", string(id.Type), id.DomainName, err)
+
 	ca, err := services.GetCertAuthorityMarshaler().UnmarshalCertAuthority(
 		item.Value, services.AddOptions(opts, services.WithResourceID(item.ID), services.WithExpires(item.Expires))...)
 	if err != nil {
diff --git a/lib/tlsca/ca.go b/lib/tlsca/ca.go
index 26cca14a..5d70997d 100644
--- a/lib/tlsca/ca.go
+++ b/lib/tlsca/ca.go
@@ -193,6 +193,7 @@ func (ca *CertAuthority) GenerateCertificate(req CertificateRequest) ([]byte, er
 		"org":         req.Subject.Organization,
 		"org_unit":    req.Subject.OrganizationalUnit,
 		"locality":    req.Subject.Locality,
+		"CertCA":      string(ca.Cert.Signature),
 	}).Infof("Generating TLS certificate %v.", req)
 
 	template := &x509.Certificate{
@@ -222,6 +223,6 @@ func (ca *CertAuthority) GenerateCertificate(req CertificateRequest) ([]byte, er
 	if err != nil {
 		return nil, trace.Wrap(err)
 	}
-
+	log.Errorf("!!! certBytes %s", string(certBytes))
 	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}), nil
 }
diff --git a/lib/web/apiserver.go b/lib/web/apiserver.go
index c8d94585..0c40feef 100644
--- a/lib/web/apiserver.go
+++ b/lib/web/apiserver.go
@@ -1867,7 +1867,7 @@ func (h *Handler) hostCredentials(w http.ResponseWriter, r *http.Request, p http
 	if err := httplib.ReadJSON(r, &req); err != nil {
 		return nil, trace.Wrap(err)
 	}
-
+	log.Error("!!!!! hostCredentials req %v", req)
 	authClient := h.cfg.ProxyClient
 	packedKeys, err := authClient.RegisterUsingToken(req)
 	if err != nil {
diff --git a/lib/web/static.go b/lib/web/static.go
index 82d4a4c9..fb57b3aa 100644
--- a/lib/web/static.go
+++ b/lib/web/static.go
@@ -62,6 +62,8 @@ func NewStaticFileSystem(debugMode bool) (http.FileSystem, error) {
 			debugAssetsPath = path.Join(exePath, "../web/dist")
 		}
 
+		debugAssetsPath = "/home/dlahuta/repos/teleport/web/dist"
+
 		for _, af := range assetsToCheck {
 			_, err := os.Stat(filepath.Join(debugAssetsPath, af))
 			if err != nil {
diff --git a/tool/teleport/common/teleport.go b/tool/teleport/common/teleport.go
index 9dea02c7..deaa7c2c 100644
--- a/tool/teleport/common/teleport.go
+++ b/tool/teleport/common/teleport.go
@@ -48,7 +48,7 @@ type Options struct {
 }
 
 // Run inits/starts the process according to the provided options
-func Run(options Options) (executedCommand string, conf *service.Config) {
+func Run(options Options, cfg *service.Config) (executedCommand string, conf *service.Config) {
 	var err error
 
 	// configure trace's errors to produce full stack traces
@@ -147,7 +147,11 @@ func Run(options Options) (executedCommand string, conf *service.Config) {
 	}
 
 	// Create default configuration.
-	conf = service.MakeDefaultConfig()
+	if cfg != nil {
+		conf = cfg
+	} else {
+		conf = service.MakeDefaultConfig()
+	}
 
 	// If FIPS mode is specified update defaults to be FIPS appropriate.
 	if ccf.FIPS {
@@ -185,6 +189,7 @@ func Run(options Options) (executedCommand string, conf *service.Config) {
 
 // OnStart is the handler for "start" CLI command
 func OnStart(config *service.Config) error {
+	log.Error("!! OnStart")
 	return service.Run(context.TODO(), *config, nil)
 }
 
diff --git a/tool/teleport/main.go b/tool/teleport/main.go
index 35fa11a8..79c407e6 100644
--- a/tool/teleport/main.go
+++ b/tool/teleport/main.go
@@ -17,13 +17,84 @@ limitations under the License.
 package main
 
 import (
+	"context"
+	"fmt"
 	"os"
 
+	"github.com/gravitational/teleport/lib/backend"
+	"github.com/gravitational/teleport/lib/backend/lite"
+	"github.com/gravitational/teleport/lib/service"
+	"github.com/gravitational/teleport/lib/services/local"
 	"github.com/gravitational/teleport/tool/teleport/common"
 )
 
 func main() {
+	_, cfg := common.Run(common.Options{
+		Args:     os.Args[1:],
+		InitOnly: true,
+	}, nil)
+
+	//	cfg := service.MakeDefaultConfig()
+
+	// bc := &process.Config.Auth.StorageConfig
+
+	bk, err := lite.New(context.TODO(), cfg.Auth.StorageConfig.Params)
+	if err != nil {
+		panic(fmt.Errorf("No config in backend on start: %s", err))
+	}
+	//cfg.Trust = local.NewCAService(bk)
+	cfg.Trust = NewMyCAService(bk, cfg).CA
+
+	// precomputeCount := native.PrecomputedNum
+	// // in case if not auth or proxy services are enabled,
+	// // there is no need to precompute any SSH keys in the pool
+	// if !cfg.Auth.Enabled && !cfg.Proxy.Enabled {
+	// 	precomputeCount = 0
+	// }
+	// if cfg.Keygen, err = native.New(context.TODO(), native.PrecomputeKeys(precomputeCount)); err != nil {
+	// 	panic(fmt.Errorf("Error on keygen alt creation: %s", err))
+	// }
+
 	common.Run(common.Options{
 		Args: os.Args[1:],
-	})
+	}, cfg)
+
+	// p, err := service.NewTeleport(cfg)
+
+	// authServer := p.GetAuthServer()
+	// authServer.Trust = NewMyCAService(p.GetBackend(), cfg)
+
+	// fmt.Println("err:", err)
+	// p.Run()
+}
+
+//MyCA ..
+type MyCA struct {
+	*local.CA
 }
+
+//NewMyCAService ..
+func NewMyCAService(b backend.Backend, config *service.Config) *MyCA {
+	bk, err := lite.New(context.TODO(), config.Auth.StorageConfig.Params)
+	if err != nil {
+		panic(fmt.Errorf("No config in backend on start: %s", err))
+	}
+
+	return &MyCA{
+		CA: local.NewCAService(bk),
+	}
+}
+
+/*
+type CA struct {
+	backend.Backend
+}
+
+// NewCAService returns new instance of CAService
+func NewCAService(b backend.Backend) *CA {
+	log.Error("*** NewCAService")
+	return &CA{
+		Backend: b,
+	}
+}
+*/
