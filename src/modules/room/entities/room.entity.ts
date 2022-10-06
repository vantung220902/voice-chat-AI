import User from 'src/modules/user/entities/User.entity';
import { BaseEntity, Column, Entity, JoinTable, ManyToMany } from 'typeorm';

@Entity()
export class Room extends BaseEntity {
  @Column('uuid', {
    primary: true,
    name: 'room_id',
    default: () => 'uuid_generate_v4()',
  })
  roomId: string;

  @Column('character varying', { name: 'room_name', length: 100 })
  roomName: string;

  @Column('character varying', { name: 'holder_id' })
  holderId: string;

  @ManyToMany(() => User, (user) => user.rooms)
  @JoinTable({
    name: 'rooms_users',
    joinColumns: [
      {
        name: 'ru_room_id',
        referencedColumnName: 'roomId',
      },
    ],
    inverseJoinColumns: [
      {
        name: 'ru_user_id',
        referencedColumnName: 'userID',
      },
    ],
  })
  users: User[];
}
