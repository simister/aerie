import { Body, Controller, Post, HttpCode, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @HttpCode(HttpStatus.OK)
  @Post('login')
  signIn(@Body() signInDto: AuthDto) {
    return this.authService.signIn(signInDto);
  }

  @Post('logout')
  logOut() {
    return this.authService.logOut();
  }

  @Post('signup')
  signUp(@Body() signUpDto: AuthDto) {
    return this.authService.signUp(signUpDto);
  }
}
