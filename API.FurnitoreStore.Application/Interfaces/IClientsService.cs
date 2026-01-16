using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using API.FurnitoreStore.Share;

namespace API.FurnitoreStore.Application.Interfaces;

public interface IClientsService
{
    IEnumerable<Client> GetAll();
    Client GetById(int id);

    bool Create(Client client);

    Client Update(Client client);

    bool Delete(int id);
}
