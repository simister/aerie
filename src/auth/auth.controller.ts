import {
  Body,
  Controller,
  Get,
  Post,
  HttpCode,
  HttpStatus,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @HttpCode(HttpStatus.OK)
  @Post('login')
  signIn(@Body() signInDto: AuthDto, @Res() res) {
    return this.authService.signIn(signInDto, res);
  }

  @Get('logout')
  signOut(@Res() res) {
    return this.authService.signOut(res);
  }

  @Post('signup')
  signUp(@Body() signUpDto: AuthDto) {
    return this.authService.signUp(signUpDto);
  }
}
