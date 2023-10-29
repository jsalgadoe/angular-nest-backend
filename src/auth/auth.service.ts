import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';

import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwr-payload';

import * as bcryptjs  from 'bcryptjs';

import { CreateUserDto , UpdateAuthDto, RegisterDto, LoginDto} from './dto';
import { User } from './entities/user.entity';
import { LoginResponse } from './interfaces/loginResponse';


@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>, 
    private jwtService: JwtService
  ){}

async create(createUserDto: CreateUserDto):Promise<User> {

    try {

      const { password, ...userData} = createUserDto

      const newUser = new this.userModel({
        password: bcryptjs.hashSync( password, 10),
        ...userData
      })

      await newUser.save();

      const {password:_,...user} = newUser.toJSON();

      return user;

    } catch (error) {
      if( error.code === 11000){
        throw new BadRequestException(`${ createUserDto.email} ya existe `);
      }
      throw new InternalServerErrorException('something terrible happen!!!');
    }
  }

async login( loginDto:LoginDto):Promise<LoginResponse>{

  console.log( loginDto );

  const { email, password } = loginDto;

  const user = await this.userModel.findOne({ email: email });

  if(!user) {
    throw new UnauthorizedException('Not valid credentials: email');
  }

  if(!bcryptjs.compareSync(password, user.password)){
    throw new UnauthorizedException('Not Valid credentials - password')
  }

  const { password:_,...rest } = user.toJSON();

  return {
      user:rest,
      token:this.getJwtToken({id:user.id})
  }

}


async register( registerDto:RegisterDto):Promise<LoginResponse>{

  const user = await this.create(registerDto)


  return {
      user:user,
      token:this.getJwtToken({id:user._id})
  }
}

  findAll():Promise<User[]> {
    return this.userModel.find();
  }

 async findUserById( user_id:string){
    const user = this.userModel.findById( user_id );
    const { password, ...rest } = (await user).toJSON();
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

  getJwtToken( payload:JwtPayload){
   const token = this.jwtService.sign(payload);
   return token;
  }
}
