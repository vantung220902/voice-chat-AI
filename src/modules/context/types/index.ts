import { Session, SessionData } from 'express-session';
import { Request } from 'express';
export type SessionContext = Session &
  Partial<SessionData> & { userID?: string; accessToken: string };
export type RequestContext = Request & {
  session: SessionContext;
};
