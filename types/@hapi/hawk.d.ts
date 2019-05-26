export namespace client {
  function authenticate(
    res: any,
    credentials: any,
    artifacts: any,
    options: any,
  ): any;
  function getBewit(uri: any, options: any): any;
  function header(uri: any, method: any, options: any): any;
  function message(host: any, port: any, message: any, options: any): any;
}
export namespace crypto {
  const algorithms: string[];
  function calculateMac(type: any, credentials: any, options: any): any;
  function calculatePayloadHash(
    payload: any,
    algorithm: any,
    contentType: any,
  ): any;
  function calculateTsMac(ts: any, credentials: any): any;
  function finalizePayloadHash(hash: any): any;
  function generateNormalizedString(type: any, options: any): any;
  const headerVersion: string;
  function initializePayloadHash(algorithm: any, contentType: any): any;
  function timestampMessage(credentials: any, localtimeOffsetMsec: any): any;
}
export const plugin: {
  plugin: {
    pkg: {
      dependencies: {
        "@hapi/b64": any;
        "@hapi/boom": any;
        "@hapi/cryptiles": any;
        "@hapi/hoek": any;
        "@hapi/sntp": any;
      };
      description: string;
      devDependencies: {
        "@hapi/code": any;
        "@hapi/hapi": any;
        "@hapi/lab": any;
      };
      keywords: any[];
      license: string;
      main: string;
      name: string;
      repository: string;
      scripts: {
        test: any;
        "test-cov-html": any;
      };
      version: string;
    };
    register: Function;
    requirements: {
      hapi: string;
    };
  };
};
export namespace server {
  function authenticate(req: any, credentialsFunc: any, options: any): any;
  function authenticateBewit(req: any, credentialsFunc: any, options: any): any;
  function authenticateMessage(
    host: any,
    port: any,
    message: any,
    authorization: any,
    credentialsFunc: any,
    options: any,
  ): any;
  function authenticatePayload(
    payload: any,
    credentials: any,
    artifacts: any,
    contentType: any,
  ): void;
  function authenticatePayloadHash(calculatedHash: any, artifacts: any): void;
  function header(credentials: any, artifacts: any, options: any): any;
}
export namespace sntp {
  function isLive(): any;
  function now(): any;
  function offset(options: any): any;
  function start(options: any): void;
  function stop(): void;
  function time(options: any): any;
}
export namespace uri {
  function authenticate(req: any, credentialsFunc: any, options: any): any;
  function getBewit(uri: any, options: any): any;
}
export namespace utils {
  const limits: {
    maxMatchLength: number;
  };
  function now(localtimeOffsetMsec: any): any;
  function nowSecs(localtimeOffsetMsec: any): any;
  function parseAuthorizationHeader(header: any, keys: any): any;
  function parseContentType(header: any): any;
  function parseHost(req: any, hostHeaderName: any): any;
  function parseRequest(req: any, options: any): any;
  function unauthorized(message: any, attributes: any): any;
  function version(): any;
}
