import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('signup')
    async signup(@Body('username') username: string,
        @Body('email') email: string,
        @Body('password') password: string) {
        return this.authService.signup(username, email, password);
    }

    @Post('login')
    async login(@Body('username') username: string,
        @Body('password') password: string) {
        return this.authService.login(username, password);
    }
}
