import { DurableObject } from "cloudflare:workers";

interface RealtimeEnv {
  APP_ENV?: string;
}

export class RealtimeRoom extends DurableObject<RealtimeEnv> {
  private readonly sessions = new Set<WebSocket>();

  constructor(
    ctx: DurableObjectState,
    env: RealtimeEnv
  ) {
    super(ctx, env);
  }

  async fetch(request: Request): Promise<Response> {
    const upgradeHeader = request.headers.get("Upgrade");

    if (upgradeHeader !== "websocket") {
      return new Response("Expected WebSocket upgrade.", { status: 426 });
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];

    this.ctx.acceptWebSocket(server);
    this.sessions.add(server);
    server.send(JSON.stringify({ type: "connected" }));

    return new Response(null, {
      status: 101,
      webSocket: client
    });
  }

  async broadcast(payload: string) {
    for (const session of this.sessions) {
      if (session.readyState === WebSocket.OPEN) {
        session.send(payload);
      }
    }
  }

  async webSocketMessage(socket: WebSocket, message: string | ArrayBuffer) {
    if (typeof message !== "string") {
      socket.send(JSON.stringify({ type: "error", message: "Text messages only." }));
      return;
    }
  }

  async webSocketClose(socket: WebSocket) {
    this.sessions.delete(socket);
  }

  async webSocketError(socket: WebSocket) {
    this.sessions.delete(socket);
  }
}
