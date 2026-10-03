package com.lattice.oidc.models;

import java.util.List;

/**
 * A device flow request awaiting the end-user's decision: shown on the device authorization page
 * and kept (bound to the browser) until the user approves or denies it.
 */
public record DeviceApproval(
    String userCode, String clientName, List<String> scopes, String[] claimNames, String[] acrs) {}
