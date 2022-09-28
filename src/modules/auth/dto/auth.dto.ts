import { Injectable } from '@nestjs/common';
import {
  IsEmail,
  IsOptional,
  IsPhoneNumber,
  IsString,
  MaxLength,
  MinLength,
  registerDecorator,
  ValidationArguments,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';
import {
  HasMimeType,
  IsFile,
  MaxFileSize,
  MemoryStoredFile,
} from 'nestjs-form-data';

@ValidatorConstraint({ name: 'isEmailOrPhone' })
@Injectable()
export class IsEmailOrPhoneConstraint implements ValidatorConstraintInterface {
  validate(emailOrPhone: string) {
    const isPhone =
      /^([+]?[\s0-9]+)?(\d{3}|[(]?[0-9]+[)])?([-]?[\s]?[0-9])+$/im.test(
        emailOrPhone,
      );
    const isEmail = /\S+@\S+\.\S+/.test(emailOrPhone);
    return isPhone || isEmail;
  }
  defaultMessage(validationArguments?: ValidationArguments): string {
    return `${validationArguments.value} be a phone number or a email address`;
  }
}

export function IsEmailOrPhone(validationOptions?: ValidationOptions) {
  return function (object: any, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsEmailOrPhoneConstraint,
    });
  };
}
export class SignInDto {
  @IsString()
  @IsEmailOrPhone()
  emailOrPhone: string;

  @IsString()
  @MinLength(8)
  @MaxLength(255)
  password: string;
}

export class SigUpDto {
  @IsString()
  @IsPhoneNumber()
  phone: string;

  @IsString()
  @IsEmail()
  email: string;

  @IsString()
  firstName: string;

  @IsString()
  lastName: string;

  @IsString()
  @MinLength(8)
  @MaxLength(255)
  password: string;

  @IsOptional()
  @IsFile()
  @MaxFileSize(1e6)
  @HasMimeType(['image/jpeg', 'image/png'])
  avatar?: MemoryStoredFile;
}
