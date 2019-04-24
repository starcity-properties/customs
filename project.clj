(defproject starcity/customs "1.2.4-SNAPSHOT"
  :description "Starcity authentication and authorization utilities"
  :license {:name "Eclipse Public License"
            :url  "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.9.0"]
                 [com.datomic/datomic-free "0.9.5544"]
                 [buddy "2.0.0"]
                 [starcity/toolbelt-datomic "0.1.0"]
                 [com.cemerick/url "0.1.1"]

                 [cheshire "5.8.0"]
                 [clj-time "0.14.4"]
                 [ring/ring-core "1.6.3"]]

  :repositories {"releases" {:url        "s3://starjars/releases"
                             :username   :env/aws_access_key
                             :passphrase :env/aws_secret_key}}

  :plugins [[s3-wagon-private "1.2.0"]])
