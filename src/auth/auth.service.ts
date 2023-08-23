import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { user } from '@prisma/client'
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    constructor(
        private prismaService: PrismaService,
        private jwtService: JwtService
    ) { }

    async login(username: string, password: string): Promise<{token: string}> {

        const user = await this.prismaService.user.findUnique({ where: { username } });

        if (!user) {
            throw new NotFoundException(`No user found for username: ${username}`);
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            throw new UnauthorizedException('Wrong Password');
        }

        const payload = { sub: user.id, username: user.username }; 
        const token = this.jwtService.sign(payload);

        return { token };
    }

    async register(username: string, password: string): Promise<user> {
        const isUserValid = await this.prismaService.user.findUnique({ where: { username } });

        if (isUserValid) {
            throw new Error('User already exists');
        }

        if (password.length < 6) {
            throw new Error('Password less than 6 characters')
        }

        const hashPassword = await bcrypt.hash(password, 8);

        const user = await this.prismaService.user.create({
            data: {
                username,
                password: hashPassword,
            },
        });

        

        return user;
    }

}

