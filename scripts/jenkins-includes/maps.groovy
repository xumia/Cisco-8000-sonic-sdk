/*
 * This file contains common maps used by our Jenkinsfile's. These
 * maps can be loaded into a variable in Jenkinsfile's by using the
 * load command.
 *
 * Example:
 *  maps = load "${params.BASE_WORKSPACE}/scripts/jenkins-includes/maps.groovy"
 */

force_run_label_map = [
    "gibraltar-ports-sanity",
    "gibraltar-extended-ports-sanity",
    "gibraltar-hw-wb-func",
    "gibraltar-matilda-3.2a-hw-func",
    "fishnet-hw-wb-gibraltar", "fishnet-hw-wb-gibraltar-sdk-upgrade"
]

run_label_map = [
  "run-all-sanity" :
    [
      "gibraltar-hw-doa",
      "gibraltar-hw-func", "gibraltar-hw-perf",
      "gibraltar-sdk-wb-simulation",
      "pacific-hw-doa",
      "pacific-hw-func", "pacific-hw-perf",
      "graphene-hw-func",
      "fishnet-hw-gibraltar", "fishnet-hw-gibraltar-udc",
      "fishnet-lc-gibraltar", "fishnet-hw-pacific",
      "fishnet-lc-pacific",
      "pacific-valgrind-api", "pacific-valgrind-lpm"
    ],
  "run-all-hw-sanity" :
    [
      "gibraltar-hw-func", "gibraltar-hw-perf",
      "pacific-hw-func", "pacific-hw-perf",
      "graphene-hw-func"
    ],
  "run-all-valgrind" :
    [
      "pacific-valgrind-api", "pacific-valgrind-lpm"
    ],
  "run-all-fishnet-hw-sanity" :
    [
      "fishnet-hw-gibraltar", "fishnet-hw-gibraltar-udc",
      "fishnet-lc-gibraltar", "fishnet-hw-pacific",
      "fishnet-lc-pacific"
    ],
  "run-all-hw-doa" :
    [
      "gibraltar-hw-doa", "pacific-hw-doa"
    ]
]

return this