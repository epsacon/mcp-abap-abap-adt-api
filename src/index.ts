#!/usr/bin/env node

import { config } from 'dotenv';
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from "express";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  McpError,
  ErrorCode
} from "@modelcontextprotocol/sdk/types.js";
import { ADTClient, session_types } from "abap-adt-api";
import type { ClientOptions } from "abap-adt-api";
import path from 'path';
import https from 'https';
import { createOAuthRouter, isValidToken } from './oauth.js';
import { AuthHandlers } from './handlers/AuthHandlers.js';
import { TransportHandlers } from './handlers/TransportHandlers.js';
import { ObjectHandlers } from './handlers/ObjectHandlers.js';
import { ClassHandlers } from './handlers/ClassHandlers.js';
import { CodeAnalysisHandlers } from './handlers/CodeAnalysisHandlers.js';
import { ObjectLockHandlers } from './handlers/ObjectLockHandlers.js';
import { ObjectSourceHandlers } from './handlers/ObjectSourceHandlers.js';
import { ObjectDeletionHandlers } from './handlers/ObjectDeletionHandlers.js';
import { ObjectManagementHandlers } from './handlers/ObjectManagementHandlers.js';
import { ObjectRegistrationHandlers } from './handlers/ObjectRegistrationHandlers.js';
import { NodeHandlers } from './handlers/NodeHandlers.js';
import { DiscoveryHandlers } from './handlers/DiscoveryHandlers.js';
import { UnitTestHandlers } from './handlers/UnitTestHandlers.js';
import { PrettyPrinterHandlers } from './handlers/PrettyPrinterHandlers.js';
import { GitHandlers } from './handlers/GitHandlers.js';
import { DdicHandlers } from './handlers/DdicHandlers.js';
import { ServiceBindingHandlers } from './handlers/ServiceBindingHandlers.js';
import { QueryHandlers } from './handlers/QueryHandlers.js';
import { FeedHandlers } from './handlers/FeedHandlers.js';
import { DebugHandlers } from './handlers/DebugHandlers.js';
import { RenameHandlers } from './handlers/RenameHandlers.js';
import { AtcHandlers } from './handlers/AtcHandlers.js';
import { TraceHandlers } from './handlers/TraceHandlers.js';
import { RefactorHandlers } from './handlers/RefactorHandlers.js';
import { RevisionHandlers } from './handlers/RevisionHandlers.js';

config({ path: path.resolve(__dirname, '../.env') });

interface SapCredentials {
  url: string;
  user: string;
  password: string;
  clientOptions: ClientOptions;
}

async function fetchJson(url: string, options: https.RequestOptions & { body?: string }): Promise<any> {
  return new Promise((resolve, reject) => {
    const { body, ...reqOpts } = options;
    const req = https.request(url, reqOpts, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString())); }
        catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function resolveCredentials(): Promise<SapCredentials> {
  const vcap = process.env.VCAP_SERVICES ? JSON.parse(process.env.VCAP_SERVICES) : null;

  if (vcap) {
    const destBinding = (vcap['destination'] || [])[0];
    const connBinding = (vcap['connectivity'] || [])[0];

    if (!destBinding) throw new Error('No destination service binding found in VCAP_SERVICES');
    if (!connBinding) throw new Error('No connectivity service binding found in VCAP_SERVICES');

    const destCreds = destBinding.credentials;
    const connCreds = connBinding.credentials;
    const destinationName = process.env.DESTINATION_NAME || 'S4H_CAL';

    // 1. Get OAuth token for destination service
    const tokenUrl = new URL(`${destCreds.url}/oauth/token`);
    const tokenBody = `grant_type=client_credentials&client_id=${encodeURIComponent(destCreds.clientid)}&client_secret=${encodeURIComponent(destCreds.clientsecret)}`;
    const tokenResp = await fetchJson(tokenUrl.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(tokenBody).toString(),
      },
      body: tokenBody,
    });
    const accessToken: string = tokenResp.access_token;
    if (!accessToken) throw new Error(`Failed to get destination service token: ${JSON.stringify(tokenResp)}`);

    // 2. Fetch the destination configuration
    const destApiUrl = `${destCreds.uri}/destination-configuration/v1/destinations/${destinationName}`;
    const destResp = await fetchJson(destApiUrl, {
      method: 'GET',
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    // destinationConfiguration is a flat key→value object in the v1 API response
    const cfg: Record<string, string> = destResp.destinationConfiguration || {};
    const sapUrl  = cfg['URL'];
    const sapUser = cfg['User'];
    const sapPass = cfg['Password'];

    if (!sapUrl || !sapUser || !sapPass) {
      throw new Error(`Destination ${destinationName} missing URL/User/Password. Response: ${JSON.stringify(destResp)}`);
    }

    // 3. Get connectivity proxy JWT (instance identity token)
    const proxyHost = connCreds.onpremise_proxy_host || 'connectivityproxy.internal';
    const proxyPort = parseInt(connCreds.onpremise_proxy_http_port || connCreds.onpremise_proxy_port || '20003', 10);

    // The connectivity proxy needs a Proxy-Authorization JWT from the connectivity service token endpoint
    const connTokenUrl = new URL(`${connCreds.token_service_url}/oauth/token`);
    const connTokenBody = `grant_type=client_credentials&client_id=${encodeURIComponent(connCreds.clientid)}&client_secret=${encodeURIComponent(connCreds.clientsecret)}`;
    const connTokenResp = await fetchJson(connTokenUrl.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(connTokenBody).toString(),
      },
      body: connTokenBody,
    });
    const proxyToken: string = connTokenResp.access_token;
    if (!proxyToken) throw new Error(`Failed to get connectivity proxy token: ${JSON.stringify(connTokenResp)}`);

    // 4. Build an https.Agent that routes through the connectivity proxy
    //    axios uses the httpsAgent for HTTPS targets; the proxy tunnel is HTTP CONNECT
    const tunnelAgent = new https.Agent({
      rejectUnauthorized: false,
      // axios will use HTTPS_PROXY / HTTP_PROXY env vars for the CONNECT tunnel
    });
    // Set proxy env vars so axios picks up the tunnel automatically
    process.env.HTTPS_PROXY = `http://${proxyHost}:${proxyPort}`;
    process.env.HTTP_PROXY  = `http://${proxyHost}:${proxyPort}`;

    return {
      url: sapUrl,
      user: sapUser,
      password: sapPass,
      clientOptions: {
        httpsAgent: tunnelAgent,
        headers: {
          'Proxy-Authorization': `Bearer ${proxyToken}`,
        },
      },
    };
  }

  // Local development — use .env values
  const missingVars = ['SAP_URL', 'SAP_USER', 'SAP_PASSWORD'].filter(v => !process.env[v]);
  if (missingVars.length > 0) {
    throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
  }

  return {
    url: process.env.SAP_URL as string,
    user: process.env.SAP_USER as string,
    password: process.env.SAP_PASSWORD as string,
    clientOptions: {},
  };
}

export class AbapAdtServer extends Server {
  private adtClient!: ADTClient;
  private authHandlers!: AuthHandlers;
  private transportHandlers!: TransportHandlers;
  private objectHandlers!: ObjectHandlers;
  private classHandlers!: ClassHandlers;
  private codeAnalysisHandlers!: CodeAnalysisHandlers;
  private objectLockHandlers!: ObjectLockHandlers;
  private objectSourceHandlers!: ObjectSourceHandlers;
  private objectDeletionHandlers!: ObjectDeletionHandlers;
  private objectManagementHandlers!: ObjectManagementHandlers;
  private objectRegistrationHandlers!: ObjectRegistrationHandlers;
  private nodeHandlers!: NodeHandlers;
  private discoveryHandlers!: DiscoveryHandlers;
  private unitTestHandlers!: UnitTestHandlers;
  private prettyPrinterHandlers!: PrettyPrinterHandlers;
  private gitHandlers!: GitHandlers;
  private ddicHandlers!: DdicHandlers;
  private serviceBindingHandlers!: ServiceBindingHandlers;
  private queryHandlers!: QueryHandlers;
  private feedHandlers!: FeedHandlers;
  private debugHandlers!: DebugHandlers;
  private renameHandlers!: RenameHandlers;
  private atcHandlers!: AtcHandlers;
  private traceHandlers!: TraceHandlers;
  private refactorHandlers!: RefactorHandlers;
  private revisionHandlers!: RevisionHandlers;

    constructor() {
    super(
      {
        name: "mcp-abap-abap-adt-api",
        version: "0.1.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );
    // adtClient and handlers are initialised in init() before run() starts accepting requests
  }

  async init(): Promise<void> {
    await this.initHandlers();
  }

  async initHandlers(): Promise<void> {
    const creds = await resolveCredentials();

    this.adtClient = new ADTClient(
      creds.url,
      creds.user,
      creds.password,
      process.env.SAP_CLIENT as string,
      process.env.SAP_LANGUAGE as string,
      creds.clientOptions
    );
    this.adtClient.stateful = session_types.stateful;

    // Initialize handlers
    this.authHandlers = new AuthHandlers(this.adtClient);
    this.transportHandlers = new TransportHandlers(this.adtClient);
    this.objectHandlers = new ObjectHandlers(this.adtClient);
    this.classHandlers = new ClassHandlers(this.adtClient);
    this.codeAnalysisHandlers = new CodeAnalysisHandlers(this.adtClient);
    this.objectLockHandlers = new ObjectLockHandlers(this.adtClient);
    this.objectSourceHandlers = new ObjectSourceHandlers(this.adtClient);
    this.objectDeletionHandlers = new ObjectDeletionHandlers(this.adtClient);
    this.objectManagementHandlers = new ObjectManagementHandlers(this.adtClient);
    this.objectRegistrationHandlers = new ObjectRegistrationHandlers(this.adtClient);
    this.nodeHandlers = new NodeHandlers(this.adtClient);
    this.discoveryHandlers = new DiscoveryHandlers(this.adtClient);
    this.unitTestHandlers = new UnitTestHandlers(this.adtClient);
    this.prettyPrinterHandlers = new PrettyPrinterHandlers(this.adtClient);
    this.gitHandlers = new GitHandlers(this.adtClient);
    this.ddicHandlers = new DdicHandlers(this.adtClient);
    this.serviceBindingHandlers = new ServiceBindingHandlers(this.adtClient);
    this.queryHandlers = new QueryHandlers(this.adtClient);
    this.feedHandlers = new FeedHandlers(this.adtClient);
    this.debugHandlers = new DebugHandlers(this.adtClient);
    this.renameHandlers = new RenameHandlers(this.adtClient);
    this.atcHandlers = new AtcHandlers(this.adtClient);
    this.traceHandlers = new TraceHandlers(this.adtClient);
    this.refactorHandlers = new RefactorHandlers(this.adtClient);
    this.revisionHandlers = new RevisionHandlers(this.adtClient);

    this.setupToolHandlers();
  }

  private serializeResult(result: any) {
    try {
      // Handlers already return a well-formed MCP tool result
      // ({ content: [...] }). Re-wrapping it would double-serialize the payload
      // (every quote in the data gets escaped again), needlessly inflating large
      // responses such as object source (issue #4). Pass those through as-is and
      // only wrap raw values (e.g. the healthcheck object).
      if (result && Array.isArray(result.content)) {
        return result;
      }
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, (key, value) =>
            typeof value === 'bigint' ? value.toString() : value
          )
        }]
      };
    } catch (error) {
      return this.handleError(new McpError(
        ErrorCode.InternalError,
        'Failed to serialize result'
      ));
    }
  }

  private handleError(error: unknown) {
    if (!(error instanceof Error)) {
      error = new Error(String(error));
    }
    if (error instanceof McpError) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            error: error.message,
            code: error.code
          })
        }],
        isError: true
      };
    }
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Internal server error',
          code: ErrorCode.InternalError
        })
      }],
      isError: true
    };
  }

  private setupToolHandlers() {
    this.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          ...this.authHandlers.getTools(),
          ...this.transportHandlers.getTools(),
          ...this.objectHandlers.getTools(),
          ...this.classHandlers.getTools(),
          ...this.codeAnalysisHandlers.getTools(),
          ...this.objectLockHandlers.getTools(),
          ...this.objectSourceHandlers.getTools(),
          ...this.objectDeletionHandlers.getTools(),
          ...this.objectManagementHandlers.getTools(),
          ...this.objectRegistrationHandlers.getTools(),
            ...this.nodeHandlers.getTools(),
            ...this.discoveryHandlers.getTools(),
            ...this.unitTestHandlers.getTools(),
            ...this.prettyPrinterHandlers.getTools(),
            ...this.gitHandlers.getTools(),
            ...this.ddicHandlers.getTools(),
            ...this.serviceBindingHandlers.getTools(),
            ...this.queryHandlers.getTools(),
            ...this.feedHandlers.getTools(),
            ...this.debugHandlers.getTools(),
            ...this.renameHandlers.getTools(),
            ...this.atcHandlers.getTools(),
            ...this.traceHandlers.getTools(),
            ...this.refactorHandlers.getTools(),
            ...this.revisionHandlers.getTools(),
            {
            name: 'healthcheck',
            description: 'Check server health and connectivity',
            inputSchema: {
              type: 'object',
              properties: {}
            }
          }
        ]
      };
    });

    this.setRequestHandler(CallToolRequestSchema, async (request) => {
      try {
        let result: any;
        
        switch (request.params.name) {
            case 'login':
            case 'logout':
            case 'dropSession':
                result = await this.authHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'transportInfo':
            case 'createTransport':
            case 'hasTransportConfig':
            case 'transportConfigurations':
            case 'getTransportConfiguration':
            case 'setTransportsConfig':
            case 'createTransportsConfig':
            case 'userTransports':
            case 'transportsByConfig':
            case 'transportDelete':
            case 'transportRelease':
            case 'transportSetOwner':
            case 'transportAddUser':
            case 'systemUsers':
            case 'transportReference':
                result = await this.transportHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'lock':
            case 'unLock':
                result = await this.objectLockHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'objectStructure':
            case 'searchObject':
            case 'findObjectPath':
            case 'objectTypes':
            case 'reentranceTicket':
                result = await this.objectHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'classIncludes':
            case 'classComponents':
                result = await this.classHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'syntaxCheckCode':
            case 'syntaxCheckCdsUrl':
            case 'codeCompletion':
            case 'findDefinition':
            case 'usageReferences':
            case 'syntaxCheckTypes':
            case 'codeCompletionFull':
            case 'runClass':
            case 'codeCompletionElement':
            case 'usageReferenceSnippets':
            case 'fixProposals':
            case 'fixEdits':
            case 'fragmentMappings':
            case 'abapDocumentation':
                result = await this.codeAnalysisHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'getObjectSource':
            case 'setObjectSource':
                result = await this.objectSourceHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'deleteObject':
                result = await this.objectDeletionHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'activateObjects':
            case 'activateByName':
            case 'inactiveObjects':
                result = await this.objectManagementHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'objectRegistrationInfo':
            case 'validateNewObject':
            case 'createObject':
                result = await this.objectRegistrationHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'nodeContents':
            case 'mainPrograms':
                result = await this.nodeHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'featureDetails':
            case 'collectionFeatureDetails':
            case 'findCollectionByUrl':
            case 'loadTypes':
            case 'adtDiscovery':
            case 'adtCoreDiscovery':
            case 'adtCompatibiliyGraph':
                result = await this.discoveryHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'unitTestRun':
            case 'unitTestEvaluation':
            case 'unitTestOccurrenceMarkers':
            case 'createTestInclude':
                result = await this.unitTestHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'prettyPrinterSetting':
            case 'setPrettyPrinterSetting':
            case 'prettyPrinter':
                result = await this.prettyPrinterHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'gitRepos':
            case 'gitExternalRepoInfo':
            case 'gitCreateRepo':
            case 'gitPullRepo':
            case 'gitUnlinkRepo':
            case 'stageRepo':
            case 'pushRepo':
            case 'checkRepo':
            case 'remoteRepoInfo':
            case 'switchRepoBranch':
                result = await this.gitHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'annotationDefinitions':
            case 'ddicElement':
            case 'ddicRepositoryAccess':
            case 'packageSearchHelp':
                result = await this.ddicHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'publishServiceBinding':
            case 'unPublishServiceBinding':
            case 'bindingDetails':
                result = await this.serviceBindingHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'tableContents':
            case 'runQuery':
                result = await this.queryHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'feeds':
            case 'dumps':
                result = await this.feedHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'debuggerListeners':
            case 'debuggerListen':
            case 'debuggerDeleteListener':
            case 'debuggerSetBreakpoints':
            case 'debuggerDeleteBreakpoints':
            case 'debuggerAttach':
            case 'debuggerSaveSettings':
            case 'debuggerStackTrace':
            case 'debuggerVariables':
            case 'debuggerChildVariables':
            case 'debuggerStep':
            case 'debuggerGoToStack':
            case 'debuggerSetVariableValue':
                result = await this.debugHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'renameEvaluate':
            case 'renamePreview':
            case 'renameExecute':
                result = await this.renameHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'atcCustomizing':
            case 'atcCheckVariant':
            case 'createAtcRun':
            case 'atcWorklists':
            case 'atcUsers':
            case 'atcExemptProposal':
            case 'atcRequestExemption':
            case 'isProposalMessage':
            case 'atcContactUri':
            case 'atcChangeContact':
                result = await this.atcHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'tracesList':
            case 'tracesListRequests':
            case 'tracesHitList':
            case 'tracesDbAccess':
            case 'tracesStatements':
            case 'tracesSetParameters':
            case 'tracesCreateConfiguration':
            case 'tracesDeleteConfiguration':
            case 'tracesDelete':
                result = await this.traceHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'extractMethodEvaluate':
            case 'extractMethodPreview':
            case 'extractMethodExecute':
                result = await this.refactorHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'revisions':
                result = await this.revisionHandlers.handle(request.params.name, request.params.arguments);
                break;
            case 'healthcheck':
                result = { status: 'healthy', timestamp: new Date().toISOString() };
                break;
            default:
                throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${request.params.name}`);
        }

        return this.serializeResult(result);
      } catch (error) {
        return this.handleError(error);
      }
    });
  }

  async run() {
    await this.init();

    const useStdio = process.argv.includes('--stdio');

    this.onerror = (error) => { console.error('[MCP Error]', error); };

    process.on('SIGINT', async () => { await this.close(); process.exit(0); });
    process.on('SIGTERM', async () => { await this.close(); process.exit(0); });

    if (useStdio) {
      const transport = new StdioServerTransport();
      await this.connect(transport);
      console.error('MCP ABAP ADT API server running on stdio');
      return;
    }

    const app = express();
    const PORT = parseInt(process.env.PORT ?? '3000', 10);
    const BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;

    // Body parsing only for OAuth and non-MCP routes; /message and /mcp handle their own body reading
    app.use((req, _res, next) => {
      if (req.path === '/message' || req.path === '/mcp') return next();
      express.json()(req, _res, () => express.urlencoded({ extended: false })(req, _res, next));
    });

    // OAuth 2.1 endpoints (unauthenticated — they ARE the auth flow)
    app.use(createOAuthRouter(BASE_URL));

    app.get('/health', (_req, res) => {
      res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
    });

    // Bearer token guard for MCP endpoints
    const requireBearer = (req: express.Request, res: express.Response, next: express.NextFunction) => {
      const auth = req.headers['authorization'];
      const token = auth?.startsWith('Bearer ') ? auth.slice(7) : null;
      if (!token || !isValidToken(token)) {
        res.setHeader('WWW-Authenticate', `Bearer realm="${BASE_URL}"`)
           .status(401)
           .json({ error: 'unauthorized', error_description: 'Valid bearer token required' });
        return;
      }
      next();
    };

    // ── Streamable HTTP transport (new spec — used by claude.ai) ──────────────
    const streamableTransport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless
    });
    await this.connect(streamableTransport);

    app.all('/mcp', requireBearer, async (req, res) => {
      await streamableTransport.handleRequest(req, res, req.body);
    });

    // ── Legacy SSE transport (used by Claude Code via .mcp.json) ─────────────
    // Each SSE connection gets its own Server instance so it doesn't conflict
    // with the streamable transport connected to `this`.
    let activeSseTransport: SSEServerTransport | null = null;
    let activeSseServer: AbapAdtServer | null = null;

    app.get('/sse', requireBearer, async (_req, res) => {
      if (activeSseTransport) {
        try { await activeSseServer?.close(); } catch (_) {}
        activeSseTransport = null;
        activeSseServer = null;
      }
      const sseServer = new AbapAdtServer();
      await sseServer.initHandlers();
      const transport = new SSEServerTransport('/message', res);
      activeSseTransport = transport;
      activeSseServer = sseServer;
      res.on('close', () => {
        if (activeSseTransport === transport) {
          activeSseTransport = null;
          activeSseServer = null;
        }
      });
      await sseServer.connect(transport);
    });

    app.post('/message', requireBearer, async (req, res) => {
      if (!activeSseTransport) {
        res.status(503).json({ error: 'No active SSE connection' });
        return;
      }
      try {
        await activeSseTransport.handlePostMessage(req, res);
      } catch (err: any) {
        console.error('[MCP] handlePostMessage error:', err?.message ?? err);
        if (!res.headersSent) {
          res.status(500).json({ error: err?.message ?? 'Internal server error' });
        }
      }
    });

    app.listen(PORT, () => {
      console.error(`MCP ABAP ADT API server running on HTTP/SSE port ${PORT}`);
    });
  }
}

// Create and run server instance
const server = new AbapAdtServer();
server.run().catch((error) => {
  console.error('Failed to start MCP server:', error);
  process.exit(1);
});
