/*
 * This file contains common functions used by our Jenkinsfile's. These
 * functions can be loaded into a variable in Jenkinsfile's by using the
 * load command.
 *
 * Example:
 *  funcs = load "${params.BASE_WORKSPACE}/scripts/jenkins-includes/funcs.groovy"
 */

import jenkins.model.CauseOfInterruption.UserInterruption

def setNormalizedJobName() {
    return "${env.JOB_NAME}".toLowerCase().replace(' ', '_').replace('-', '_')
}

def setNormalizedBranchName() {
    return "${env.GIT_BRANCH}".replace("/","%252F")
}

def is_regression(include_master_pr = false) {
    if (include_master_pr) {
        return env.NORMALIZED_JOB_NAME.contains("leaba_sdk") || env.NORMALIZED_JOB_NAME.contains("master_pr") 
    } else {
        return env.NORMALIZED_JOB_NAME.contains("leaba_sdk")
    }
}

def shouldRunStage(String stageName) {
  // Allows the submitter to specify the stages to run through the commit title
  // by providing "run_only_stage=<CSV>" where the stages are lowercase and
  // hyphenated instead of space separated strings.
  // "run_only_stages=gibraltar-sdk-simulation" would run only the required builds
  // and "Gibraltar SDK Simulation", skipping everything else.

  String commitTitle = gitCommitTitle.toLowerCase();
  String newStageName = stageName.replace(' ', '-').toLowerCase();

  if (commitTitle.indexOf('run_only_stages=') == -1) {
      return true;
  }

  def matcher = commitTitle =~ /(?s)^.*run_only_stages=([a-zA-Z_0-9-]*,)*${newStageName}(,[a-zA-Z_0-9-]*)*.*/
  Boolean matches = matcher.find();
  if (matches) {
    echo("stage name  " +  newStageName + " matches!!!");
  } else {
    echo("stage name " + newStageName + " does not match commit title: " + commitTitle);
  }

  return matches;
}

/*
 * filesChangedIn()
 *
 * Return true if files were changed in any of the provided search_patterns.
 * One or more regex pattern can be provided for the search pattern(s), but the method must be
 * called multiple times if using multiple search modes (NORMAL/INVERSE).
 *
 * Param: mode - Determines whether to do an inclusive (NORMAL) or exclusive (INVERSE) search
 * Param: search_patterns - pattern list containing directories, filenames, or other patterns
 * to compare with diff. The global Interface<List> "patterns" is used in conjunction with
 * this param.
 *
 * The basic formula used is as follows:
 * all changes outside of an inverse search list + all changes in the normal list
 * will trigger the stage. Inverse lists end in "_inv".
 * Not all stages use both modes, but the formula is the same.
 *
 * Example:
 * PC HW Func
 *   runStageIf(filesChangedIn(SearchMode.INVERSE, patterns.pc_inv)
 *           || filesChangedIn(SearchMode.NORMAL, patterns.pc))
 * List pc_inv       = ["^driver.*", "^devices.*", "^sai.*", "^fishnet.*", "^npl/gibraltar.*"]
 * List pc           = ["^driver/pacific.*", "^driver/shared.*", "^devices/pacific.*"]
 *
 * In this case, we will ignore changes to any file within the "pc_inv" list of directories (will
 * not trigger the stage), but will trigger for all other paths. Additionally, we will trigger the
 * stage if any files are changed in one or more directories in the "pc" list. This means that
 * driver/gibraltar will NOT trigger PC HW Func but driver/pacific and driver/shared will.
 */
def filesChangedIn(SearchMode mode, List<String> search_patterns) {

  // Compare only local changes vs. the target branch
  def int result = 0
  def String searchModeString = ''

  if (mode == SearchMode.INVERSE) {
    // delete all entries containing any of the patterns, then count remaining list
    def Collection remaining_file_list = changedFileList
    searchModeString = 'INVERSE'

    for (String pattern : search_patterns) {
      remaining_file_list.removeAll { it ==~ pattern }
    }

    result = remaining_file_list.size()
  } else {
    // Search list for every provided pattern and add up number of matches
    searchModeString = 'NORMAL'

    for (String pattern : search_patterns) {
      def numOccurrences = changedFileList.count { it ==~ pattern }
      result += numOccurrences
    }
  }

  def String pattern_string = ''
  for (String pattern : search_patterns) {
    pattern_string += pattern.trim() + '\n'
  }

  if (result) {
    echo "Found $result files changed using $searchModeString search with the regex pattern(s):\n$pattern_string"
    return true
  } else {
    echo "No changed files found using $searchModeString search with the regex pattern(s):\n$pattern_string"
    return false
  }
}


def labelFoundToRunStage(String stage) {
  // Return true if this PR is labeled with the appropriate label to allow the stage to run, false otherwise.
  // Param: stageName - string of a pipeline stage to be looked up in the PR labels

  String stageName = stage.replace(' ','-').toLowerCase();
  String stageLabel = "run-${stageName}"
  Boolean run_stage = false;

  if (!maps.run_label_map["run-all-sanity"].contains(stageName)) {
    if (maps.force_run_label_map.contains(stageName)) {
      if (prLabels.contains(stageLabel)) {
        echo "Forcefully running Stage: ${env.STAGE_NAME}";
        run_stage = true;
      } else {
        echo "${env.STAGE_NAME} requires the following label to run: ${stageLabel}";
      }
    } else {
      run_stage = true;
    }
  } else {
    prLabels.each{ label ->
      stage_list = maps.run_label_map[label]
      if (stage_list != null && stage_list.contains(stageName)) {
        run_stage = true;
      } else if (label == stageLabel) {
        run_stage = true;
      }
    }
  }

  if (run_stage) {
    echo "labelFoundToRunStage() is returning TRUE for ${stage}"
  } else if (!force_run_label_map.contains(stageName)) {
    echo "labelFoundToRunStage() is returning FALSE for ${stage}"
    setBuildStatus(resultStatus.PENDING, "Skipped. Please set run-all-sanity or ${stageLabel}")
  }

  return run_stage;
}

def runStageIf(Boolean condition) {
  // Return true if the stage should be run
  if (skipPassedOnReplay(env.STAGE_NAME)) {
    echo "Skipping \"$env.STAGE_NAME\" because it previously passed on the same commit ID"
    setBuildStatus(resultStatus.SUCCESS, resultMessage.PREV_SUCCESS)
    return false
  } else if (condition) {
    def ret = labelFoundToRunStage(env.STAGE_NAME) && shouldRunStage(env.STAGE_NAME)
    if (ret) {
      echo "Running \"$env.STAGE_NAME\""
    } else {
      echo "Not running \"$env.STAGE_NAME\""
    }
    return ret
  } else {
    echo "Skipping \"$env.STAGE_NAME\" because diff criteria were not met"
    setBuildStatus(resultStatus.SUCCESS, resultMessage.SKIPPED)
    return false
  }
}

def getMailAddressOfLastCommitter() {
  def result = sh(
      script: """#!/bin/bash
      git show -s --format='%ae'
      """,
      returnStdout: true).trim();
  return result.trim()
}

void emailPRResults() {
  def errSubjectExt = ''
  def prTitle = gitPRData['title']

  // Truncate PR Title for email to 40 chars (including ...)
  if (prTitle.length() > 40) {
    prTitle = prTitle.take(37) + "..."
  }
  // Extend the subject to include the failed stage for FAILURE/UNSTABLE results
  if (currentBuild.currentResult == "FAILURE" || currentBuild.currentResult == "UNSTABLE") {
    errSubjectExt = " at stage '$failedStage'"
  }

  // Sends email to the user who initiated the build and last git committer
  emailext(subject: "SDK PR-$env.CHANGE_ID #$env.BUILD_ID: $prTitle - \$BUILD_STATUS" + errSubjectExt,
            body: '''${SCRIPT, template="groovy-html.template"}''',
            recipientProviders: [[$class: 'RequesterRecipientProvider']],
            to: getMailAddressOfLastCommitter())
}

void emailRegressionResults(boolean earlyNotice = false) {
  // Sends email to all the people who caused a change in the change set, to the user who initiated the build,
  // to the list of users who committed a change since the last non-broken build till now and the relevant mailer
  // or DE

  // Initialize default email values, which may be overridden below
  def errSubjectExt = ''
  def emailBody = '''${SCRIPT, template="groovy-html.template"}'''
  def recipient = ''

  if (earlyNotice) {
    // "early notice" failures for PRs add a note to the start of the email body
    emailBody = '''This is an early notification that a stage has failed. Other parallel stages may still be in progress.
                  \nAn overall status will be sent out once they complete.
                  \n\n''' + emailBody
  }

  if (is_regression()) {
    // Baseline regression runs for protected branches are part of the "Leaba SDK" job
    if (earlyNotice) {
      // "early notice" failures that are part of baseline runs also override the recipient to
      // a reduced audience to expedite the debugging process without spamming
      recipient = 'jenkins-sdk-infra@cisco.com'
    } else {
      recipient = 'leaba.sdk.dev@cisco.com'
    }
    recipientGroups = [[$class: 'DevelopersRecipientProvider'],
                       [$class: 'RequesterRecipientProvider'],
                       [$class: 'CulpritsRecipientProvider']]
  } else {
    // PRs testing Jenkinsfile.regression changes will avoid notifying any mailers
    recipient = getMailAddressOfLastCommitter()
    recipientGroups = [[$class: 'RequesterRecipientProvider']]
  }

  if (currentBuild.currentResult == "FAILURE") {
    // Extend the subject to include the failed stage
    // Final notice uses *first* failure (recorded in 'failedStage'), while early notices are for each failure
    if (earlyNotice) {
      errSubjectExt = " at stage '$env.STAGE_NAME'"
    } else {
      errSubjectExt = " at stage '$failedStage'"
    }
  } else if(currentBuild.currentResult == "UNSTABLE") {
    // Extend the subject to include the unstable stage
    // Final notice uses *first* caught error (recorded in 'unstableStage'), while early notices are for each caught error
    if (earlyNotice) {
      errSubjectExt = " at stage '$env.STAGE_NAME'"
    } else {
      errSubjectExt = " at stage '$unstableStage'"
    }
  }

  emailext(subject: "\$PROJECT_NAME #$env.BUILD_ID - \$BUILD_STATUS" + errSubjectExt,
            body: emailBody,
            recipientProviders: recipientGroups,
            to: recipient)
}

def emailResults(boolean earlyNotice = false) {
    if (is_regression(include_master_pr: true)) {
        emailRegressionResults(earlyNotice)
    } else {
        emailPRResults()
    }
}

// Utilizes the curl API to update the stage result in Github for a PR or Regression
void postBuildStatus(String status, String message) {
    // add a Github access token as a global 'secret text' credential on Jenkins with the id 'github-commit-status-token'
    // https://jenkins.leaba.local/credentials/
    withCredentials([string(credentialsId: 'git_write_access_token', variable: 'TOKEN')]) {
        // 'set -x' for debugging. Don't worry the access token won't be actually logged
        // Also, the sh command actually executed is not properly logged, it will be further escaped when written to the log
        def statusUrl =  "$env.GIT_API_URL/statuses/$env.GIT_COMMIT?access_token=$TOKEN"
        def stageName = "${env.STAGE_NAME}"
        if (is_regression(include_master_pr: true)) {
            stageName = "Regression-${env.STAGE_NAME}"
        }
        sh """#!/bin/bash
        set - x
        curl \"${statusUrl}\" \
                -H \"Content-Type: application/json\" \
                -X POST \
                -d '{"description": "$message", "state": "$status", "context": "$stageName", "target_url": "$env.BUILD_URL"}'
        """
    }
}

def initChangesFile(repo) {
  def changesFile = "$workspace/pr_file_list.txt"
  // Fetch the target branch so that we can compare our checked out branch to it for changes
  withCredentials([usernamePassword(credentialsId: 'marvin_faceless', passwordVariable: 'GIT_PASSWORD', usernameVariable: 'GIT_USERNAME'),
                  string(credentialsId: 'git_write_access_token', variable: 'TOKEN')]) {
    def result = sh(
        script: """#!/bin/bash -x
          git fetch --no-tags -- https://${GIT_USERNAME}:${TOKEN}@${repo} +refs/heads/${env.CHANGE_TARGET}:refs/remotes/origin/${env.CHANGE_TARGET}
        """,
        returnStdout: true).trim();
  }

  def changed_file_string = sh(
    script: """#!/bin/bash -x
      git --no-pager diff --name-only `git merge-base origin/${env.CHANGE_TARGET} HEAD`
    """, returnStdout: true).trim()

  changedFileList = changed_file_string.split('\n')
  echo "${env.CHANGE_ID}'s list of changed files: ${changedFileList}"

  writeFile(file: changesFile, text: changed_file_string)

  return changesFile
}

def initGitPRData(gitApiUrl, prNum) {
  // Return the labels that are applied to the Github PR
  def url = "$gitApiUrl/issues/"
  def prDataFile = "$workspace/github_pr_data.json"

  withCredentials([string(credentialsId: 'git_write_access_token', variable: 'TOKEN')]) {
    sh """#!/bin/bash -x
      /auto/asic-tools/sw/python/3.6.10/bin/python3.6 ${workspace}/scripts/github_data.py --pr ${prNum} --url ${url} --access_token ${TOKEN} --json_to_file $prDataFile
    """
  }
  // Read JSON data from file to global map
  gitPRData = readJSON file: prDataFile

  // Initialize PR label list
  for (label in gitPRData['labels']) {
    prLabels.add(label['name'])
  }

  echo "${prNum}'s list of labels: ${prLabels}"
  return prDataFile
}

// Set Build Status and sends email notifications for regressions
void setBuildStatus(String status, String message = resultMessage.DEFAULT) {
    if (message == resultMessage.DEFAULT) {
      switch(status) {
        case resultStatus.SUCCESS:
        message = resultMessage.SUCCESS
        break;
        case resultStatus.FAILURE:
        message = resultMessage.FAILURE
        break;
        case resultStatus.PENDING:
        message = resultMessage.PENDING
        break;
        default:
        error "Must specify resultMessage. Build status \"$status\" does not have a default set."
      }
    }

    if (status == resultStatus.SUCCESS && message == resultMessage.SUCCESS
        && !is_regression(include_master_pr: true)) {
      // create <replayDir>/<stage>.passed file on success
      def stage_result_filename = getResultFileName stage: env.STAGE_NAME
      sh """#!/bin/bash
        touch ${stage_result_filename}
      """
    }

    postBuildStatus(status, message)

    if (is_regression()) {
        //Regression Version
        if (status == resultStatus.FAILURE) {
        // send an email immediately in case we are in a parallel stage that might run other parallel tasks for
        // several hours or even a day before ending the pipeline. Reduce recipients to leads and culprits. Final
        // result will go to the full team later
        if (currentBuild.currentResult == "FAILURE") {
            if (failedStage == "Unknown") {
            failedStage = env.STAGE_NAME
            }
        } else if (currentBuild.currentResult == "UNSTABLE") {
            if (unstableStage == "Unknown") {
            unstableStage = env.STAGE_NAME
            }
        }

        emailRegressionResults(true)
        }
    } else {
        //PR Version
        if (status == resultStatus.FAILURE && failedStage == "Unknown") {
            failedStage = env.STAGE_NAME
        }
    }
}

/*
 * Helps set the first Failed Stage in Jenkins, as well as captures
 * and sets Unstable results for Fishnet tests.
 */
void updateBuildStatus(hudson.AbortException exc) {
    echo exc.message;
    def m = exc.message =~ /(?i)script returned exit code (\d+)/
    if (m) {
        def exitcode = m.group(1).toInteger()
        if (exitcode == 1) {
            // script exit code will be 1 if no errors and there are failed tests
            echo "There are failed tests"
            currentBuild.result = 'UNSTABLE';
            failedStage = env.STAGE_NAME
        } else if (exitcode == 143) {
            // script exit code will be 143 if Aborted by other stage
            echo "Stage aborted"
            currentBuild.result = 'ABORTED';
        } else if (exitcode > 0) {
            echo "Exit code greater than zero, stage failed"
            currentBuild.result = 'FAILURE';
            failedStage = env.STAGE_NAME
            sh("exit 1")
        }
    }
}

Boolean skipPassedOnReplay(String stage) {
  // Check if there was a previous successful run of this stage for the same commit hash.
  // That would indicate this is a replay and we do not need to run this stage.
  if (fileExists(getResultFileName(stage: env.STAGE_NAME))) {
    return true
  } else {
    return false
  }
}

void abortPreviousBuilds() {
    def isAbortedBuild = false
    Run previousBuild = currentBuild.rawBuild.getPreviousBuildInProgress()
    while (previousBuild != null) {
        isAbortedBuild = true
        if (previousBuild.isInProgress()) {
            def executor = previousBuild.getExecutor()
            if (executor != null) {
                echo ">> Aborting older build #${previousBuild.number}"
                executor.interrupt(Result.ABORTED, new UserInterruption("Aborted by newer build #${currentBuild.number}"))
            }
        }
        previousBuild = previousBuild.getPreviousBuildInProgress()
    }
    if (isAbortedBuild) {
       echo "Aborted PreviousBuildInProgress"
    }
}

// Determines if PR is marked as HP in the PR Whitelist,
// then sets lockPriority to the appropriate value.
String setLockableResourcePriority(String dataString) {
  def String highPriority = "1"
  def String lowPriority  = "0"
  def String prHpList = readFile("${env.CAG_JENKINS_ROOT}/lr-priority-prs/pr_hp_whitelist.txt")

  if (dataString.isNumber()){
    // If dataString is just a number, this is a Pull Request
    if (prHpList.contains(dataString)) {
      echo "Running all HW Stages as HP (PR in HP list)"
      return highPriority
    } else {
      echo "Running all HW Stages as LP (PR not in HP list)"
      return lowPriority
    }
  } else {
    // If dataString is NOT a number, the dataString is the job name
    if (dataString.contains("leaba_sdk")) {
      echo "Running all HW Stages as HP (part of Leaba SDK job)"
      return highPriority
    } else {
      echo "Running all HW Stages as LP (not part of Leaba SDK job)"
      return lowPriority
    }
  }
}

return this
