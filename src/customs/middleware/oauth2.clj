(ns customs.middleware.oauth2
  (:require #_[clj-http.client :as http]
    [org.httpkit.client :as http]
    [cemerick.url :as url]
    [cheshire.core :as json]
    [clj-time.core :as time]
    [clojure.string :as str]
    [crypto.random :as random]
    [ring.util.codec :as codec]
    [ring.util.request :as request]
    [ring.util.response :as resp]
    [ring.util.response :as response]
    [taoensso.timbre :as timbre]))

;; Oauth 2.0 middleware based off of ring-oauth2 (https://github.com/weavejester/ring-oauth2),
;; with adjustments to make it handle the Implicit Grant as well as the Authorization Code Grant.
;; More information about Oauth 2.0 grants:
;; https://community.apigee.com/articles/41719/when-to-use-which-oauth2-grants-and-oidc-flows.html

;; ==============================================================================
;; URI helpers ==================================================================
;; ==============================================================================

(defn- parse-uri-path [uri]
  (.getPath (java.net.URI. uri)))


(defn- absolute-uri [uri request]
  (-> (request/request-url request)
      (url/url uri)
      str))


(defn- make-authorize-uri [{:keys [authorize-uri response-type redirect-uri]
                            :or   {response-type "token"}
                            :as   profile} {:keys [query-params] :as req} state]
  (str authorize-uri
    (if (.contains ^String authorize-uri "?") "&" "?")
    (codec/form-encode
      (merge query-params
        {:response_type (str response-type)
         :client_id     (str (:client-id profile))
         :redirect_uri  (absolute-uri redirect-uri (dissoc req :query-string))
         :state         (str state)}))))


;; ==============================================================================
;; Launch authorization =========================================================
;; ==============================================================================

(defn- random-state []
  (-> (random/base64 9) (str/replace "+" "-") (str/replace "/" "_")))


(defn- launch-handler [profile]
  (fn [{:keys [session] :or {session {}} :as request}]
    (let [state (or (::state session) (random-state))]
      (-> (response/redirect (make-authorize-uri profile request state))
          (assoc :session (assoc session ::state state))))))


;; ==============================================================================
;; Access token =================================================================
;; ==============================================================================


(defn- format-access-token
  [{:keys [body] :as r}]
  (let [{:keys [access_token expires_in refresh_token id_token] :as b} (json/parse-string body keyword)]
    (-> {:token access_token}
        (cond-> expires_in (assoc :expires (-> expires_in time/seconds time/from-now))
                refresh_token (assoc :refresh-token refresh_token)
                id_token (assoc :id-token id_token)))))


(defn- get-access-token
  [{:keys [access-token-uri redirect-uri client-id client-secret basic-auth?]
    :or   {basic-auth? false} :as profile} request]
  (format-access-token
    @(http/post access-token-uri
                {:accept      :json
                 :form-params {:grant_type    "authorization_code"
                               :code          (get-in request [:query-params "code"])
                               :redirect_uri  (absolute-uri redirect-uri request)
                               :client_id     client-id
                               :client_secret client-secret}})))


(defn- assoc-access-tokens [request]
  (if-let [tokens (-> request :session ::access-tokens)]
    (assoc request :oauth2/access-tokens tokens)
    request))


;; ==============================================================================
;; Redirects ====================================================================
;; ==============================================================================


(defn- redirect-handler
  "Handle redirects. The client (browser) should include a state parameter in the query so we
  can verify the request is not a CSRF attack.

  If state matches, exchange the temporary code for an access token with a request to the :access-token-uri."
  [{:keys [landing-uri landing-uri-key] :as profile} state-matches? access-token-fn]
  (fn [{:keys [session] :as request}]
    (let [state-mismatch-handler (fn [_]
                                   {:status 400, :headers {}, :body "State mismatch"})
          error-handler          (:state-mismatch-handler profile state-mismatch-handler)
          landing-uri            (or landing-uri (get-in request [:params landing-uri-key]))]
      (if state-matches?
        (-> (resp/redirect (or landing-uri "/"))
          (assoc :session (-> session
                            (assoc ::access-tokens (access-token-fn))
                            (assoc ::state nil))))
        (error-handler request)))))


(defn- code-grant-redirect-handler
  "Handle redirects according to the authorization code grant, where the auth service returns a code that
  we can exchange for an access token. The client (browser) should include a state parameter in the query so we
  can verify the request is not a CSRF attack.

  The request should include a 'code' query parameter, which will be exchanged for an access token by
  a request to the :access-token-uri setup in the profile."
  [profile]
  (fn [request]
    (letfn [(-state-matches? [req]
              (= (get-in req [:session ::state])
                 (get-in req [:query-params "state"])))]
      ((redirect-handler profile
                         (-state-matches? request)
                         #(get-access-token profile request)) request))))


(defn- implicit-grant-redirect-handler
  "Handle redirects according to the implicit grant. The client performs a POST request, including a :state
  parameter so we can verify the request is not a CSRF attack.

  The request should include a :token param with the access token."
  [profile]
  (fn [{:keys [params] :as request}]
    (letfn [(-state-matches? [req]
              (= (get-in req [:session ::state])
                 (get-in req [:params :state])))
            (-token-fn []
              {:token (:token params)})]
      ((redirect-handler profile
                         (-state-matches? request)
                         -token-fn) request))))


;; ==============================================================================
;; Middleware ===================================================================
;; ==============================================================================


(defn wrap-oauth2
  "Ring middleware that acts as a Oauth2. The profile has the following
  options:

  :authorize-uri    - 3rd party URI to redirect the user to log in.
  :access-token-uri - 3rd party URI to exchange a code for an access token.
  :launch-uri       - URI that kicks off the authorization process.
  :redirect-uri     - Callback URI where the browser is redirected after authorization has been granted.
  :landing-uri      - URI to redirect the user upon completed authentication.
  :response-type    - String identifying what flow to use, #{'token', 'code'}
                      Use 'token' for implicit grant, and 'code for authorization code grant.

  Note: a post request to the :redirect-uri can be used in the implicit grant flow to set the session cookie
  for the appliation."
  [handler {:keys [response-type launch-uri redirect-uri] :as profile}]
  (fn [{:keys [uri] :as request}]
    (cond (= (parse-uri-path launch-uri) uri)
          ((launch-handler profile) request)

          (= (parse-uri-path redirect-uri) uri)
          (if (= response-type "code")
            ((code-grant-redirect-handler profile) request)
            (if (= :post (:request-method request))
              ((implicit-grant-redirect-handler profile) request)
              (handler request)))

          :otherwise
          (handler (assoc-access-tokens request)))))