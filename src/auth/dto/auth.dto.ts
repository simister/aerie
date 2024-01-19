import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class AuthDto {
  @IsEmail()
  public email: string;

  @IsNotEmpty()
  @IsString()
  @Length(8, 255, {
    message: 'Password must be between 8 and 255 characters in length.',
  })
  public password: string;
}
