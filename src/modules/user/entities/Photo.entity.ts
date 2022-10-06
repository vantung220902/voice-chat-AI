import { Column, Entity, OneToOne } from 'typeorm';
import User from './User.entity';

@Entity()
export class Photo {
  @Column('uuid', {
    primary: true,
    default: () => 'uuid_generate_v4()',
  })
  id: string;

  @Column('character varying')
  url: string;

  @Column('character varying', { name: 'public_id' })
  publicId: string;

  @OneToOne(() => User, (user) => user.photo)
  user: User;
}
