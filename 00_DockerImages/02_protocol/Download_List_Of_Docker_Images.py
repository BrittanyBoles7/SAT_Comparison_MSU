# by Derek Reimanis

import os
import sys
import time
import json
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait

from GlobalFunctions.Symbolic_Link import link

projects = [
    "sl","photon","yourls","wordpress","postfixadmin",
    "nextcloud", "matomo","phpmyadmin","mediawiki",
    "joomla","backdrop","xwiki","geonetwork",
    "websphere-liberty","open-liberty","zookeeper",
    "clojure","storm", "gradle","solr","groovy","sonarqube",
    "flink","orientdb","neo4j","lightstreamer","kapacitor",
    "sapmachine","kong","mariadb","ibmjava","eclipse-temurin",
    "swift","odoo","arangodb","convertigo","unit","cassandra","spark",
    "amazoncorretto","plone","amazonlinux","clearlinux","tomcat","julia",
    "haproxy","ghost","hylang","satosa","rakudo-star","rabbitmq","rust",
    "silverpeas","tomee","ibm-semeru-runtimes","hitch","eclipse-mosquitto",
    "dart",
    "maven","haskell","caddy","swipl","redis","ros","friendica","redmine",
    "haxe","influxdb","node","ruby","telegraf","golang","gcc","elixir","spiped",
    "memcached","rethinkdb","perl","pypy","r-base","varnish","irssi","nginx","mono",
    "httpd","erlang","emqx","buildpack-deps","chronograf","adminer","aerospike","postgres",
    "couchdb","debian","jetty","crate","jruby","percona","mysql","oraclelinux",
    "elasticsearch","fluentd","logstash","znc","vault","traefik","eggdrop","consul",
    "bash","api-firewall","nats","alpine","python","fedora","couchbase","gazebo",
    "ubuntu","archlinux","alt","kibana","busybox","almalinux","nats-streaming","monica",
    "composer","neurodebian","bonita","cirros","rockylinux","hello-world","notary","teamspeak",
    "express-gateway","jobber","mongo-express","adoptopenjdk","rapidoid","centos","php-zendserver",
    "nuxeo","fsharp","sourcemage","mageia","crux","sentry","euleros","thrift","known",
    "hola-mundo","hello-seattle","owncloud","piwik","jenkins","swarm","celery","iojs",
    "glassfish","django","rails","hipache","docker-dev","ubuntu-upstart","ubuntu-debootstrap"

]


def export_to_json(master_map):
    # link this output to the input of next step iff not already done, which we check by seeming if shadow folder exists because it's created when linked
    path = str(Path(sys.path[0]).absolute().parent) + "/04_product/"

    with open(path+'docker-projects-'+str(len(projects))+'-benchmark.json', "w") as outfile:
        json.dump(master_map, outfile, indent=2)


def main():
    driver = webdriver.Chrome()
    wait = WebDriverWait(driver, 10)
    master_map = {'images': []}
    for project in projects:
        project_versions = []
        webpage = "https://hub.docker.com/_/" + project + "/tags"
        driver.get(webpage)
        time.sleep(3)
        #page counter, start at 2 because page 1 is the default tags page
        page_increment = 2;
        i = 0
        while True:
            # base case, this is a bit of a do-while loop
            final_page_elements = driver.find_elements(By.XPATH, "//div[@class='MuiTypography-root MuiTypography-subtitle1 css-1dufp5b']")
            # only get the first 10 versions, or if less than 10 versions exist do that. We don't need every version
            if len(final_page_elements) > 0 or i >= 10:   # and final_page_elements[0].text == "Tags not retrieved"
                break
            versions = driver.find_elements(By.XPATH, "//a[@class='MuiTypography-root MuiTypography-inherit MuiLink-root MuiLink-underlineAlways css-1nqtld6' and @data-testid='navToImage']")

            for element in versions:
                # ignore latest, because latest is a duplicate of the one after latest
                if element.text != 'latest':
                    i = i + 1
                    project_versions.append(element.text)
                    print(element.text)
            next_page = webpage + "?page=" + str(page_increment)
            driver.get(next_page)
            # wait for page to load
            time.sleep(5)
            page_increment += 1
        master_map['images'].append({"name":project, "versions": project_versions})
    driver.quit()
    export_to_json(master_map)


if __name__ == "__main__":
    main()