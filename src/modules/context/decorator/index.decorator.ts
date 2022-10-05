import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { RequestContext } from 'src/modules/context/types';
export const ContextSession = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const request: RequestContext = ctx.switchToHttp().getRequest();
    return request;
  },
);
