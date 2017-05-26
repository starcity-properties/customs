(ns customs.access
  (:require [buddy.auth :refer [authenticated? throw-unauthorized]]
            [buddy.auth.accessrules :refer [error success]]
            [buddy.auth.backends.session :refer [session-backend]]))

;; =============================================================================
;; Constants
;; =============================================================================

(def ^:private permissions {})

;; =============================================================================
;; Access Rules
;; =============================================================================

(defn- get-role [req]
  (get-in req [:session :identity :account/role]))

(defn authenticated-user [req]
  (if (authenticated? req)
    true
    (throw-unauthorized)))

(defn unauthenticated-user [req]
  (not (authenticated? req)))

(defn user-can
  "Given a particular action that the authenticated user desires to perform,
  return a handler that determines if their user level is authorized to perform
  that action."
  [action]
  (fn [req]
    (let [user-role      (get-role req)
          required-roles (get permissions action #{})]
      (if (some #(isa? user-role %) required-roles)
        (success)
        (error (format "User with role %s is not authorized for action %s"
                       (name user-role) (name action)))))))

(defn user-isa
  "Return a handler that determines whether the authenticated user is of a
  specific role OR any derived role."
  [role]
  (fn [req]
    (if (isa? (get-role req) role)
      (success)
      (error (format "User is not a(n) %s" (name role))))))

(defn user-is
  "Return a handler that determines whether the authenticated user is of a
  specific role."
  [role]
  (fn [req]
    (if (= (get-role req) role)
      (success)
      (error (format "User is not a(n) %s" (name role))))))

(defn user-has-id
  "Return a handler that determines whether the authenticated user has a given ID.
  This is useful, for example, to determine if the user is the owner of the
  requested resource."
  [id]
  (fn [req]
    (if (= id (get-in req [:identity :db/id]))
      (success)
      (error (str "User does not have id given %s" id)))))

;; =============================================================================
;; Auth Backend
;; =============================================================================

(defn- response [body status]
  {:status  status
   :body    body
   :headers {"Content-Type" "text/html; charset=utf-8"}})

(defn auth-backend
  "Authentication/authorization backend for ring middlewares."
  [& {:keys [unauthorized-handler]}]
  (letfn [(-default-handler [{:keys [headers] :as request} metadata]
            (if (authenticated? request)
              (response "You are not authorized to view this page." 403)
              (response "You are not authenticated; please log in." 401)))]
    (session-backend {:unauthorized-handler (or unauthorized-handler -default-handler)})))
