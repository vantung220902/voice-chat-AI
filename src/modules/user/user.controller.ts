import { UpdateUserDto } from './dto/user.dto';
import { JwtGuard } from './../auth/guard/jwt.guard';
import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Put,
  UseGuards,
  Param,
} from '@nestjs/common';
import { GetUser } from '../auth/decorator';
import User from 'src/entities/User.entity';
import { UserService } from './user.service';
import { FileSystemStoredFile, FormDataRequest } from 'nestjs-form-data';
import { ParseUUIDPipe } from '@nestjs/common/pipes';

@UseGuards(JwtGuard)
@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}
  @Get()
  me(@GetUser() user: User) {
    return user;
  }

  @Put(':id')
  @FormDataRequest({ storage: FileSystemStoredFile })
  @HttpCode(HttpStatus.OK)
  update(
    @Param('id', new ParseUUIDPipe()) id: string,
    @Body() dto: UpdateUserDto,
  ) {
    return this.userService.updateUser(id, dto);
  }
}
