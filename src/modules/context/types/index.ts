import { Session, SessionData } from 'express-session';
import { Request } from 'express';
export type SessionContext = Session &
  Partial<SessionData> & { userId?: string; accessToken: string };
export type RequestContext = Request & {
  session: SessionContext;
};
