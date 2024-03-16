import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
} from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { Reflector } from '@nestjs/core';
import { AUTH_SERVICE } from '../constants/services';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly logger = new Logger(JwtAuthGuard.name);

  constructor(
    @Inject(AUTH_SERVICE) private readonly authClient: ClientProxy,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context?.switchToHttp()?.getRequest();

    const jwt =
      request.cookies?.Authentication || request.headers?.authentication;

    if (!jwt) {
      return false;
    }
    // const resp = await this.authClient.validateToken(jwt);
    const resp = await this.authClient.send('validateToken', {
      Authentication: jwt,
    });
    console.log('----------auth lafda-------', resp, request);
    request.decodedData = resp;
    return true;
  }
  catch(error) {
    console.log('auth error - ', error.message);
    throw new ForbiddenException(
      error.message || 'session expired! Please sign In',
    );
  }
}
