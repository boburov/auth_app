import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schemas';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class AuthService {
    constructor(@InjectModel(User.name) private userModel: Model<User>) { }

    async signup(username: string, email: string, password: string): Promise<User> {
        const exsisting = await this.userModel.findOne({ email });
        if (exsisting) throw new Error('User already exists');

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new this.userModel({ username, email, password: hashedPassword });
        await newUser.save();

        return newUser;
    }

    async login(username: string, password: string): Promise<User> {
        const user = await this.userModel.findOne({ username });
        if (!user) throw new Error('User not found');

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) throw new Error('Invalid password');

        const token = jwt.sign({ id: user._id, username: user.username }, 'SECRET', {
            expiresIn: '1d',
        });


        return token;
    }

}
