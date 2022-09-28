import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { RequestContext } from 'src/config/context';

export const GetUser = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const request: Express.Request = ctx.switchToHttp().getRequest();
    if (data) {
      return request.user[data];
    }
    return request.user;
  },
);

export const ContextSession = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const request: RequestContext = ctx.switchToHttp().getRequest();
    return request;
  },
);
