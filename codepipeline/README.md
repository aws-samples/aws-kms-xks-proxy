<!--
    Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
-->

This folder stores the scripts used by `AWS CodeDeploy` in a CodePipeline environment.  The scripts become available to `AWS CodeDeploy` in a pipeline once the content of this folder is pushed to `AWS CodeCommit`.

Note this directory and the `appspec.yml` in the root directory are closely related.  Together they must be pushed to `AWS CodeCommit` to get used by `AWS CodeDeploy` in a pipeline environment.

