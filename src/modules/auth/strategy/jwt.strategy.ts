import { RequestContext } from 'src/config/context';
import { Injectable, ForbiddenException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthServices } from './../auth.service';
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    config: ConfigService,
    private readonly authService: AuthServices,
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
      iat: number;
      exp: number;
    },
  ) {
    const user = await this.authService.findUserById(payload.sub);
    if (!user || userID !== user?.userID)
      throw new ForbiddenException('Credentials taken');
    delete user.password;
    return user;
  }
}
