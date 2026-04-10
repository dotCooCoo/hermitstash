/**
 * Shared WebAuthn helpers for base64url encoding and credential formatting.
 */
(function() {
  function base64urlToBuffer(b64url) {
    var b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    var bin = atob(b64);
    var arr = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr.buffer;
  }

  function bufferToBase64url(buf) {
    var bytes = new Uint8Array(buf);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  // Prepare WebAuthn get options (convert challenge + allowCredentials from base64url)
  function prepareGetOptions(options) {
    options.challenge = base64urlToBuffer(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map(function(c) {
        c.id = base64urlToBuffer(c.id);
        return c;
      });
    }
    return options;
  }

  // Prepare WebAuthn create options (convert challenge + user.id + excludeCredentials)
  function prepareCreateOptions(options) {
    options.challenge = base64urlToBuffer(options.challenge);
    options.user.id = base64urlToBuffer(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map(function(c) {
        c.id = base64urlToBuffer(c.id);
        return c;
      });
    }
    return options;
  }

  // Format a credentials.get() response for the server
  function formatGetResponse(credential) {
    return {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: bufferToBase64url(credential.response.authenticatorData),
        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
        signature: bufferToBase64url(credential.response.signature),
        userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null
      },
      authenticatorAttachment: credential.authenticatorAttachment || null,
      clientExtensionResults: credential.getClientExtensionResults()
    };
  }

  // Format a credentials.create() response for the server
  function formatCreateResponse(credential) {
    return {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: bufferToBase64url(credential.response.attestationObject),
        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
        transports: credential.response.getTransports ? credential.response.getTransports() : []
      },
      authenticatorAttachment: credential.authenticatorAttachment || null,
      clientExtensionResults: credential.getClientExtensionResults()
    };
  }

  window.WebAuthnHelpers = {
    base64urlToBuffer: base64urlToBuffer,
    bufferToBase64url: bufferToBase64url,
    prepareGetOptions: prepareGetOptions,
    prepareCreateOptions: prepareCreateOptions,
    formatGetResponse: formatGetResponse,
    formatCreateResponse: formatCreateResponse
  };
})();
