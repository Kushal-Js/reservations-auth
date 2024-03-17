import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { AUTH_SERVICE } from '../constants/services';
import { Observable, catchError, map, of, tap } from 'rxjs';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly logger = new Logger(JwtAuthGuard.name);

  constructor(@Inject(AUTH_SERVICE) private readonly authClient: ClientProxy) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request = context?.switchToHttp()?.getRequest();

    const jwt =
      request.cookies?.Authentication || request.headers?.authentication;

    if (!jwt) {
      return false;
    }

    return this.authClient
      .send('validateToken', {
        Authentication: jwt,
      })
      .pipe(
        tap((res) => {
          const userId = res?.userId;
          if (userId == null || userId == '') {
            throw new UnauthorizedException();
          }
          return true;
        }),
        map(() => true),
        catchError((err) => {
          this.logger.error(err);
          return of(false);
        }),
      );
  }
}
