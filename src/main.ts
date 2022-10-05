import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import session from 'express-session';
import { __prod__ } from './constants';
import MongoStore from 'connect-mongo';

(async () => {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
    }),
  );
  app.use(
    session({
      name: process.env.COOKIE_NAME,
      store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
      cookie: {
        maxAge: 1000 * 60 * 60, // one hour
        httpOnly: true, // JS front end cannot access the cookie
        secure: __prod__, // cookie only works in https
        sameSite: 'none',
      },
      secret: process.env.SESSION_SECRET_DEV_PROD as string,
      saveUninitialized: false, // don't save empty sessions, right from the start
      resave: false,
    }),
  );
  await app.listen(process.env.PORT || 1234);
})();
