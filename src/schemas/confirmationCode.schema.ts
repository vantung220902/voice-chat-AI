import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type ConfirmationCodeDocument = ConfirmationCode & Document;

@Schema({ timestamps: true })
export class ConfirmationCode {
  @Prop({
    length: 6,
  })
  code: string;

  @Prop({})
  userID: string;
}

export const ConfirmationCodeSchema =
  SchemaFactory.createForClass(ConfirmationCode);
ConfirmationCodeSchema.index({ createdAt: 1 }, { expireAfterSeconds: 300 });
