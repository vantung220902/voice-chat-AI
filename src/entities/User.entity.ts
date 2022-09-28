import { BaseEntity, Column, Entity } from 'typeorm';
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
  public get fullName() {
    return this.firstName + ' ' + this.lastName;
  }
}
export default User;
