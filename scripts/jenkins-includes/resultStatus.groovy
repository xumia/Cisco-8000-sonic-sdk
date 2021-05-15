/*
 * This file contains the common statusess used to update GitHub Pull
 * Requests and Revisions by our Jenkinsfile's. These statuses can
 * be loaded into a variable in Jenkinsfile's by using the load command.
 *
 * Example:
 *  resultStatus = load "${params.BASE_WORKSPACE}/scripts/jenkins-includes/resultStatus.groovy"
 */

def interface status {
    String SUCCESS = "success"
    String FAILURE = "failure"
    String PENDING = "pending"
}

return status