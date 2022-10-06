import {
  BaseEntity,
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToMany,
  OneToMany,
  OneToOne,
  UpdateDateColumn,
} from 'typeorm';
import { Message } from './../../message/entities/message.entity';
import { Room } from './../../room/entities/room.entity';
import { Photo } from './Photo.entity';
export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
}
@Entity()
class User extends BaseEntity {
  @Column('uuid', {
    primary: true,
    name: 'user_id',
    default: () => 'uuid_generate_v4()',
  })
  userID: string;

  @Column('character varying', { name: 'first_name', length: 255 })
  firstName: string;

  @Column('character varying', { name: 'last_name', length: 255 })
  lastName: string;

  @Column('character varying', { length: 255 })
  password: string;

  @Column({ name: 'phone_number', length: 20, unique: true })
  phone: string;

  @Column('character varying', { length: 255, unique: true })
  email: string;

  @Column('integer', { default: 0, name: 'token_version' })
  tokenVersion?: number;

  @Column('enum', {
    enum: UserRole,
    default: UserRole.USER,
  })
  role: UserRole;

  @Column('uuid', {
    name: 'photo_id',
    nullable: true,
    unique: true,
  })
  photoId?: string | null;

  @OneToOne(() => Photo, (photo) => photo.user)
  @JoinColumn({ name: 'photo_id', referencedColumnName: 'id' })
  photo: Photo;

  @ManyToMany(() => Room, (rooms) => rooms.users)
  rooms: Room[];

  @OneToMany(() => Message, (message) => message.user)
  messages: Message[];

  @CreateDateColumn({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP(6)',
  })
  created_at: Date;

  @UpdateDateColumn({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP(6)',
    onUpdate: 'CURRENT_TIMESTAMP(6)',
  })
  updated_at: Date;

  public get fullName() {
    return this.firstName + ' ' + this.lastName;
  }
}
export default User;
