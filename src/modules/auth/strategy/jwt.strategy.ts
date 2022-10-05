import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { RequestContext } from 'src/modules/context/types';
import { UserService } from 'src/modules/user/user.service';
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    config: ConfigService,
    private readonly userService: UserService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get('JWT_SECRET'),
      passReqToCallback: true,
    });
  }
  async validate(
    { session: { userID } }: RequestContext,
    payload: {
      sub: string;
      email: string;
      role: string;
      tokenVersion: number;
      iat: number;
      exp: number;
    },
  ) {
    const user = await this.userService.findUserById(payload.sub);
    if (
      !user ||
      userID !== user.userID ||
      payload.tokenVersion !== user.tokenVersion
    )
      throw new ForbiddenException('Credentials taken');
    delete user.password;
    return user;
  }
}
