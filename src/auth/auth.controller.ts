import { Controller, Post, Body, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { user } from '@prisma/client'

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('login')
    async login(@Body() body: { username: string; password: string }) {
        const { username, password } = body;

        const user = await this.authService.login(username, password);

        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }
///muhahaha
        const tokenResponse = await this.authService.login(username, password);
        return tokenResponse; 
    }
    
    @Post('register')
    async register(@Body() body: { username: string, password: string }):Promise<user> {
        const { username, password } = body;
        return this.authService.register(username, password);
    }
}
