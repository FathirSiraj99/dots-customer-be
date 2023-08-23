import { Body, Controller, Delete, Get, Param, Post, Put } from '@nestjs/common';
import { UserService } from './user.service';
import { user } from '@prisma/client'

@Controller('user')
export class UserController {
    constructor(private userService: UserService) { }

    @Get()
    async findAll(): Promise<user[]> {
        return await this.userService.findAll()
    }

    @Get(':id')
    async findById(@Param('id') id: string): Promise<user> {
        return await this.userService.findById(id)
    }

    @Post()
    async createData(@Body() data: { username: string, password: string }): Promise<user> {
        return await this.userService.createData(data)
    }

    @Put(':id')
    async updateData(@Param('id') id: string, @Body() data: { username: string, password: string }): Promise<user> {
        return await this.userService.updateData(id, data)
    }

    @Delete(':id')
    async deleteData(@Param('id') id: string): Promise<user> {
        return await this.userService.deleteData(id)
    }
}
