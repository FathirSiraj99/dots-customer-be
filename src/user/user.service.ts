import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { user } from '@prisma/client'

@Injectable()
export class UserService {
    constructor(private prismaService: PrismaService) { }

    async findAll(): Promise<user[]> {
        return this.prismaService.user.findMany()
    }

    async findById(id: string): Promise<user> {
        return this.prismaService.user.findFirst()
    }

    async createData(
        data: { username: string, password: string }): Promise<user> {
        return this.prismaService.user.create({ data })
    }

    async updateData(
        id: string, data: { username: string, password: string }): Promise<user> {
        return this.prismaService.user.update({
            where: { id },
            data,
        })
    }

    async deleteData(id: string): Promise<user> {
        return this.prismaService.user.delete({ where: { id } })
    }

}
