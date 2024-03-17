import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { UserDocument } from '@app/common';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import { TokenPayload } from './interfaces/token-payload.interface';
import { UsersService } from './users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async login(user: UserDocument, response: Response) {
    const tokenPayload: TokenPayload = {
      userId: user._id.toString(),
    };

    const expires = new Date();
    expires.setSeconds(
      expires.getSeconds() + this.configService.get('JWT_EXPIRATION'),
    );

    const token = this.jwtService.sign(tokenPayload);

    response.cookie('Authentication', token, {
      httpOnly: true,
      expires,
    });

    return token;
  }

  validateToken(token: any) {
    const jwtToken = token?.Authentication;
    const secret = this.configService.get('JWT_SECRET');
    console.log('---------incoming token--------', jwtToken);
    console.log('---------incoming token--------', secret);
    const parsedData = this.jwtService.verify(jwtToken, secret);
    const userData = this.usersService.getUser({ _id: parsedData.userId });
    console.log('---------parsedData--------', parsedData, userData);
    return parsedData;
  }
}
