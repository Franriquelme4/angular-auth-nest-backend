import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectConnection, InjectModel } from '@nestjs/mongoose';
import { Connection, Model } from 'mongoose';
import { User } from './entities/user.entity';
import { JwtService } from '@nestjs/jwt';


import * as bcryptjs from 'bcryptjs';
import { LoginDto } from './dto/login.dto';
import { JwtPayload } from './interfaces/jwt-payload.interfaces';
import { LoginResponse } from './interfaces/login-response.interface';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService
  ) { }


  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      // 1=Encriptar la contraseña 
      const { password, ...userData } = createUserDto;
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      });

      //2=Guardar el usuario
      await newUser.save();
      const { password: _, ...user } = newUser.toJSON();
      return user;
    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already exists!`)
      }
      throw new InternalServerErrorException(`Something terrible happen`)
    }
  }

  async register(registerDto: RegisterDto): Promise<LoginResponse> {
    const user = await this.create(registerDto);
    return {
      user: user,
      token: await this.getJwtToken({ id: user._id })
    }

  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException(`No valid Credentials - email`);
    }
    if (!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException(`No valid Credentials - password`)
    }

    const { password: _, ...rest } = user.toJSON();

    return {
      user: rest,
      token: await this.getJwtToken({ id: user.id })
    }
    // {c
    //   user:  aaaaa 
    //   token: abc abc acb
    // }
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(userID: string): Promise<User> {
    const user = await this.userModel.findById(userID);
    const { password, ...rest } = user.toJSON();
    return rest;
  }


  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }


}
