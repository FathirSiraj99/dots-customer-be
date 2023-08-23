import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { user } from '@prisma/client'
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
    constructor(private prismaService: PrismaService) { }

    async login(username: string, password: string): Promise<user> {

        const user = await this.prismaService.user.findUnique({ where: { username } });

        if (!user) {
            throw new NotFoundException(`No user found for username: ${username}`);
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid password');
        }

        return user;
    }

    async register(username: string, password: string): Promise<user> {
        const isUserValid = await this.prismaService.user.findUnique({where: { username }});

        if (isUserValid) {
            throw new Error('User already exists');
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

