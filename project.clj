(defproject starcity/customs "1.0.0-SNAPSHOT"
  :description "Starcity authentication and authorization utilities"
  :license {:name "Eclipse Public License"
            :url  "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.9.0"]
                 [com.datomic/datomic-free "0.9.5544"]
                 [buddy "1.3.0"]
                 [starcity/toolbelt-datomic "0.1.0"]]

  :repositories {"releases" {:url        "s3://starjars/releases"
                             :username   :env/aws_access_key
                             :passphrase :env/aws_secret_key}}

  :plugins [[s3-wagon-private "1.2.0"]])
